package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// EmulatorOpResult is the bounded result of a dynamic operation. It is defined
// here, next to the interface that consumes it, so the agent package stays
// independent of the server; the server aliases these types.
type EmulatorOpResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// EmulatorLaunch is the typed intent a dynamic operation may send. It is
// deliberately not a free-form argument list: the sidecar validates each field
// against the Android identifier charset and builds a fixed adb argv.
type EmulatorLaunch struct {
	Component string            `json:"component"`
	Kind      string            `json:"kind,omitempty"`
	Action    string            `json:"action,omitempty"`
	Data      string            `json:"data,omitempty"`
	MIME      string            `json:"mime,omitempty"`
	Extras    map[string]string `json:"extras,omitempty"`
}

// AndroidEmulator is the dynamic half of mobile testing: the operations that
// need a running device. The server implements it; when it is nil (emulator
// disabled, or a build without the sidecar) every tool here reports that
// dynamic testing is unavailable rather than failing obscurely.
//
// The interface is deliberately narrow and typed. There is no Run(command)
// method: a model cannot turn a pentest step into an arbitrary shell command
// through this surface.
type AndroidEmulator interface {
	// Ready reports whether a booted emulator exists for this task.
	Ready(taskID string) bool
	// Install installs the package bytes as the task's target app.
	Install(ctx context.Context, taskID string, apk []byte) (EmulatorOpResult, error)
	// Launch starts one component with a validated intent.
	Launch(ctx context.Context, taskID string, launch EmulatorLaunch) (EmulatorOpResult, error)
	// Logs reads recent logcat output.
	Logs(ctx context.Context, taskID, tag string, lines int) (EmulatorOpResult, error)
	// Packages lists installed third-party packages.
	Packages(ctx context.Context, taskID string) (EmulatorOpResult, error)
}

// emulatorUnavailable is the shared message for a build or deployment without a
// ready device. It names the reason so a model does not read silence as
// "no vulnerable component found".
const emulatorUnavailable = "no Android emulator is ready for this task. Dynamic proof requires the optional emulator profile on a Linux host with /dev/kvm. Static analysis via analyze_apk is unaffected, and the static findings remain static observations until a device is available."

// installTargetAPK installs the task's APK into the running emulator.
//
// It is a write tool: installing changes device state, and two installs running
// concurrently on one emulator would race. Launch is a write tool for the same
// reason. Only the observation tools (logcat, package list) are read-only.
func (t *ToolSet) installTargetAPK() actool.CoreTool {
	return writeTool(
		"install_target_apk",
		"Install an Android package into this task's running emulator so it can be exercised. Pass the path of an APK in the workspace; the tool uploads the file itself. Returns the installer output.\n\n"+
			"This is the first step of dynamic testing and it needs the optional emulator profile. Installing is not itself a finding: it makes the app present so a hostile intent can reach it. Pair it with launch_component and read_logcat.",
		obj(map[string]any{
			"path": str("path to the APK file in the workspace"),
		}, "path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input: %v", err)), nil
			}
			path := strings.TrimSpace(a.Path)
			if path == "" {
				return actool.Errorf("path is required"), nil
			}
			if t.emulator == nil || !t.emulator.Ready(t.taskKey()) {
				return actool.Text(emulatorUnavailable), nil
			}
			apk, err := readBoundedFile(path, maxInstallBytes)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("cannot read %s: %v", path, err)), nil
			}
			res, err := t.emulator.Install(ctx, t.taskKey(), apk)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("install failed: %v", err)), nil
			}
			return actool.Text(renderOpResult("install_target_apk", res)), nil
		},
	)
}

// launchComponent sends a hostile intent at an exported component.
func (t *ToolSet) launchComponent() actool.CoreTool {
	return writeTool(
		"launch_component",
		"Start an Android component with an intent you control, to test whether an exported component is reachable in a meaningful way. This is the hostile-app step from the mobile-apk skill: point it at a component analyze_apk reported as EXPORTED and watch what happens with read_logcat.\n\n"+
			"Component must be package/class (a leading dot means the package's own namespace). kind is activity, service, or broadcast. Extras are string-only.\n\n"+
			"An accepted intent that does nothing observable is not a finding. Only report an exported component when you can show the effect.",
		obj(map[string]any{
			"component": str("package/class, e.g. com.target.app/.AdminActivity"),
			"kind":      str("activity (default), service, or broadcast"),
			"action":    str("intent action, e.g. android.intent.action.VIEW"),
			"data":      str("intent data URI"),
			"mime":      str("MIME type for the intent"),
			"extras": map[string]any{
				"type":        "object",
				"description": "string extras as a JSON object, e.g. {\"url\": \"https://attacker.test\"}",
			},
		}, "component"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Component string            `json:"component"`
				Kind      string            `json:"kind"`
				Action    string            `json:"action"`
				Data      string            `json:"data"`
				MIME      string            `json:"mime"`
				Extras    map[string]string `json:"extras"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input: %v", err)), nil
			}
			if strings.TrimSpace(a.Component) == "" {
				return actool.Errorf("component is required"), nil
			}
			if t.emulator == nil || !t.emulator.Ready(t.taskKey()) {
				return actool.Text(emulatorUnavailable), nil
			}
			res, err := t.emulator.Launch(ctx, t.taskKey(), EmulatorLaunch{
				Component: a.Component,
				Kind:      a.Kind,
				Action:    a.Action,
				Data:      a.Data,
				MIME:      a.MIME,
				Extras:    a.Extras,
			})
			if err != nil {
				return actool.Errorf(fmt.Sprintf("launch failed: %v", err)), nil
			}
			return actool.Text(renderOpResult("launch_component", res)), nil
		},
	)
}

// readLogcat returns recent device logs as evidence.
func (t *ToolSet) readLogcat() actool.CoreTool {
	return readTool(
		"read_logcat",
		"Read recent logcat output from this task's emulator. Use it immediately after launch_component to capture what the component actually did: a logged exception, a URL the WebView loaded, a file path written outside the sandbox.\n\n"+
			"Optionally filter by a log tag. The output is the evidence for a dynamic finding; quote the relevant lines rather than summarising them.",
		obj(map[string]any{
			"tag":   str("optional logcat tag filter, e.g. ActivityManager"),
			"lines": map[string]any{"type": "integer", "description": "number of recent lines, default 200, max 2000"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Tag   string `json:"tag"`
				Lines int    `json:"lines"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input: %v", err)), nil
			}
			if t.emulator == nil || !t.emulator.Ready(t.taskKey()) {
				return actool.Text(emulatorUnavailable), nil
			}
			res, err := t.emulator.Logs(ctx, t.taskKey(), a.Tag, a.Lines)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("logcat failed: %v", err)), nil
			}
			return actool.Text(renderOpResult("read_logcat", res)), nil
		},
	)
}

// listEmulatorPackages confirms what the device actually has installed.
func (t *ToolSet) listEmulatorPackages() actool.CoreTool {
	return readTool(
		"list_emulator_packages",
		"List third-party packages installed in this task's emulator. Use it to confirm the target package is present before launching a component, and to check for a package you expect the app to install at runtime.",
		obj(map[string]any{}),
		func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
			if t.emulator == nil || !t.emulator.Ready(t.taskKey()) {
				return actool.Text(emulatorUnavailable), nil
			}
			res, err := t.emulator.Packages(ctx, t.taskKey())
			if err != nil {
				return actool.Errorf(fmt.Sprintf("package list failed: %v", err)), nil
			}
			return actool.Text(renderOpResult("list_emulator_packages", res)), nil
		},
	)
}

// renderOpResult formats an operation result. Failures are reported as failures
// so the model does not read a refusal as an empty result.
func renderOpResult(tool string, res EmulatorOpResult) string {
	if !res.OK {
		reason := res.Reason
		if reason == "" {
			reason = "the operation did not succeed"
		}
		return fmt.Sprintf("%s failed: %s", tool, reason)
	}
	out := strings.TrimSpace(res.Output)
	if out == "" {
		return tool + ": succeeded with no output"
	}
	return tool + ":\n" + out
}

// maxInstallBytes bounds a package the tools will upload. It matches the
// sidecar's own limit so a file is refused here rather than streamed and
// rejected there.
const maxInstallBytes = 256 << 20

// readBoundedFile reads at most limit bytes. os.ReadFile would happily load a
// multi-gigabyte file into memory and take the agent process down with it.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file is %d bytes, larger than the %d byte limit", info.Size(), limit)
	}
	buf := make([]byte, info.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// taskKey is the numeric task id as a string, empty when unknown.
func (t *ToolSet) taskKey() string {
	if t.taskID <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", t.taskID)
}
