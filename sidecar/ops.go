package main

// Dynamic-operation surface for the emulator sidecar.
//
// Everything here exists so a task can actually exercise an app the way the
// mobile-apk skill's dynamic stage requires: install the package, start a
// component with attacker-controlled extras, and read the resulting log. What
// it deliberately does not offer is a shell. There is no endpoint that accepts
// an arbitrary command string, and no argument is ever handed to a shell: each
// operation is a fixed adb argv with values that passed the validators below.
//
// Validation is intentionally strict and closed-form. Android identifiers are
// ASCII, so anything outside that set is rejected rather than escaped; this
// removes shell metacharacters, whitespace, quotes and control characters from
// the question entirely.

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// maxExtras bounds how much attacker-supplied text one launch can carry.
	maxExtras = 16
	// maxValue bounds a single extra value.
	maxValue = 4096
	// maxInstallBytes bounds an uploaded package.
	maxInstallBytes = 256 << 20
	// maxLogLines bounds a logcat read.
	maxLogLines = 2000
)

// Android identifiers: letters, digits, underscore, dot, and (for components)
// a leading `.` shorthand. `$` is legal inside a class name for inner classes.
var (
	packagePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$`)
	componentPattern = regexp.MustCompile(`^[A-Za-z0-9_.$]+$`)
	keyPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
)

// LaunchRequest is the typed form of `am start` / `am startservice` /
// `am broadcast`. Every field is validated; nothing is passed through as a
// preformatted argument list.
type LaunchRequest struct {
	// Component is "package/.Class" or "package/full.Class".
	Component string            `json:"component"`
	// Kind is "activity" (default), "service", or "broadcast".
	Kind   string            `json:"kind,omitempty"`
	Action string            `json:"action,omitempty"`
	Data   string            `json:"data,omitempty"`
	MIME   string            `json:"mime,omitempty"`
	Extras map[string]string `json:"extras,omitempty"`
	// String extras only. Typed extras (int/bool) would need another
	// validator; string extras cover intent-redirection and WebView cases.
	Type string `json:"type,omitempty"`
}

// OpResult is what a dynamic operation returns. Output is bounded by the
// driver before it reaches here.
type OpResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// validateLaunch checks every field and returns the normalised request.
func validateLaunch(req LaunchRequest) (LaunchRequest, error) {
	out := LaunchRequest{
		Component: strings.TrimSpace(req.Component),
		Kind:      strings.ToLower(strings.TrimSpace(req.Kind)),
		Action:    strings.TrimSpace(req.Action),
		Data:      strings.TrimSpace(req.Data),
		MIME:      strings.TrimSpace(req.MIME),
		Type:      strings.TrimSpace(req.Type),
	}

	// Component must be package/class. Reject a bare package: `am start -n`
	// needs the class, and accepting a bare package would silently mean
	// "resolve the launcher", which is a different operation.
	pkg, class, ok := strings.Cut(out.Component, "/")
	if !ok || pkg == "" || class == "" {
		return out, errors.New("component must be package/class")
	}
	if !packagePattern.MatchString(pkg) {
		return out, errors.New("invalid package name")
	}
	if !componentPattern.MatchString(class) {
		return out, errors.New("invalid component class")
	}
	// A leading dot is shorthand for the package's own namespace.
	if strings.HasPrefix(class, ".") {
		class = pkg + class
	}
	out.Component = pkg + "/" + class

	switch out.Kind {
	case "":
		out.Kind = "activity"
	case "activity", "service", "broadcast":
	default:
		return out, errors.New("kind must be activity, service, or broadcast")
	}

	if out.Action != "" && !componentPattern.MatchString(out.Action) {
		return out, errors.New("invalid action")
	}
	// `-d` takes a URI. Allow URI punctuation but no whitespace or control
	// characters, which is what would let a value split an argument.
	if out.Data != "" && !validText(out.Data, 2048) {
		return out, errors.New("invalid data uri")
	}
	if out.MIME != "" && !validText(out.MIME, 128) {
		return out, errors.New("invalid mime type")
	}
	if out.Type != "" && !validText(out.Type, 128) {
		return out, errors.New("invalid type")
	}

	if len(req.Extras) > maxExtras {
		return out, errors.New("too many extras")
	}
	if len(req.Extras) > 0 {
		out.Extras = make(map[string]string, len(req.Extras))
		for k, v := range req.Extras {
			if !keyPattern.MatchString(k) {
				return out, errors.New("invalid extra key")
			}
			if !validText(v, maxValue) {
				return out, errors.New("invalid extra value")
			}
			out.Extras[k] = v
		}
	}
	return out, nil
}

// validText rejects anything that is not printable UTF-8 text. Whitespace is
// allowed because extras legitimately contain spaces; it cannot split an argv
// element because these values are passed as their own argv entries, never
// concatenated into a command line.
func validText(s string, limit int) bool {
	if s == "" {
		return true
	}
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || r == '\n' || r == '\r' || r == '\t' {
			return false
		}
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// launchArgs builds the fixed `am` argv. It is separate from execution so the
// argument construction can be asserted in tests without a device.
func launchArgs(req LaunchRequest) []string {
	args := []string{"shell", "am"}
	switch req.Kind {
	case "service":
		args = append(args, "startservice")
	case "broadcast":
		args = append(args, "broadcast")
	default:
		args = append(args, "start")
	}
	args = append(args, "-n", req.Component)
	if req.Action != "" {
		args = append(args, "-a", req.Action)
	}
	if req.Data != "" {
		args = append(args, "-d", req.Data)
	}
	if req.MIME != "" {
		args = append(args, "-t", req.MIME)
	}
	// Deterministic order so a given request always produces the same argv.
	if len(req.Extras) > 0 {
		keys := make([]string, 0, len(req.Extras))
		for k := range req.Extras {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			args = append(args, "--es", k, req.Extras[k])
		}
	}
	return args
}

// accelUsable decides whether `emulator -accel-check` output proves usable
// hardware acceleration. It exists because the obvious check — "the output
// mentions kvm" — is a false positive: the failure messages mention KVM too
// ("KVM is installed but not accessible", "KVM requires a CPU that supports vmx
// or svm"), and only the numeric status and the "usable" wording distinguish
// them. It also cannot rely on the exit status alone, which some emulator builds
// report as 0 even when acceleration is unavailable.
//
// Expected shape on success:
//
//	accel:
//	0
//	KVM (version 12) is installed and usable.
//	accel
func accelUsable(out string) bool {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	status := ""
	for i, line := range lines {
		if strings.TrimSpace(line) != "accel:" {
			continue
		}
		for _, next := range lines[i+1:] {
			if trimmed := strings.TrimSpace(next); trimmed != "" {
				status = trimmed
				break
			}
		}
		break
	}
	if status != "0" {
		return false
	}
	return strings.Contains(strings.ToLower(out), "usable")
}

// sortStrings is a tiny insertion sort so this file needs no imports beyond the
// standard library subset already used.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
