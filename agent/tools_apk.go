package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/zakirkun/EyeOfG0d/mobile"
)

// analyzeAPK is the agent-facing entry point for Android package analysis.
//
// It is a read-only tool: it opens the APK the operator placed in the workspace
// and returns structured facts. Nothing is written outside the returned value,
// so it can be given to every agent without widening what a run can do.
func (t *ToolSet) analyzeAPK() actool.CoreTool {
	return readTool(
		"analyze_apk",
		"Statically analyse an Android package (APK) in the workspace and return its security-relevant structure: package identity, manifest flags, signing scheme and certificate, exported components, deep links, permissions, native libraries, and hardcoded credentials found in the dex and native code.\n\n"+
			"This is deterministic and runs on the file itself; no device, emulator or decompiler is involved. It reports what the package declares, not what the app does at runtime: an exported component is a reachable surface, and proving it exploitable needs a device (see the mobile-apk skill's dynamic section).\n\n"+
			"Call it once per package and work from the result. Every finding it returns cites the manifest element or file that justifies it, so report_finding can use that as evidence.",
		obj(map[string]any{
			"path": str("path to the APK file, absolute or relative to the workspace"),
			"include_secret_scan": map[string]any{
				"type":        "boolean",
				"description": "also scan the dex string pool and native libraries for hardcoded credentials (default true; set false for a fast structural-only pass)",
			},
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path              string `json:"path"`
				IncludeSecretScan *bool  `json:"include_secret_scan"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input: %v", err)), nil
			}
			pathArg := strings.TrimSpace(a.Path)
			if pathArg == "" {
				return actool.Errorf("path is required"), nil
			}

			withSecrets := true
			if a.IncludeSecretScan != nil {
				withSecrets = *a.IncludeSecretScan
			}

			var (
				info     *mobile.PackageInfo
				findings []mobile.Finding
				err      error
			)
			if withSecrets {
				info, findings, err = mobile.AnalyseWithSecrets(pathArg)
			} else {
				info, err = mobile.Analyse(pathArg)
				if err == nil {
					findings = mobile.Evaluate(info)
				}
			}
			if err != nil {
				return actool.Errorf(fmt.Sprintf("cannot analyse %s: %v", pathArg, err)), nil
			}

			return actool.Text(renderAPKAnalysis(info, findings, withSecrets)), nil
		},
	)
}

// renderAPKAnalysis formats the result for the model. It is plain text rather
// than JSON because the model reasons better over a labelled summary, and the
// structured detail is already ordered by severity.
func renderAPKAnalysis(info *mobile.PackageInfo, findings []mobile.Finding, withSecrets bool) string {
	var b strings.Builder

	fmt.Fprintf(&b, "APK analysis: %s\n", info.Path)
	fmt.Fprintf(&b, "Digest: sha256:%s (%d bytes)\n", info.SHA256, info.Size)
	fmt.Fprintf(&b, "Package: %s\n", info.Summary())
	if info.MinSDK != "" || info.TargetSDK != "" {
		fmt.Fprintf(&b, "SDK: min=%s target=%s\n", orDashStr(info.MinSDK), orDashStr(info.TargetSDK))
	}
	b.WriteString("\n")

	b.WriteString("Signing\n")
	if !info.Signed {
		b.WriteString("  unsigned: no v1/v2/v3 signature found\n")
	} else {
		var schemes []string
		if info.SigningV1 {
			schemes = append(schemes, "v1")
		}
		if info.SigningV2 {
			schemes = append(schemes, "v2")
		}
		if info.SigningV3 {
			schemes = append(schemes, "v3")
		}
		fmt.Fprintf(&b, "  schemes: %s\n", strings.Join(schemes, ", "))
		for _, s := range info.Signatures {
			fmt.Fprintf(&b, "  subject: %s\n", s.Subject)
			fmt.Fprintf(&b, "    sha256: %s\n", s.SHA256)
			fmt.Fprintf(&b, "    valid: %s .. %s\n", s.NotBefore.Format("2006-01-02"), s.NotAfter.Format("2006-01-02"))
			if s.IsDebugCert {
				b.WriteString("    NOTE: this is the shared Android debug certificate\n")
			}
		}
	}
	b.WriteString("\n")

	writeComponents := func(label string, cs []mobile.Component) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s (%d)\n", label, len(cs))
		for _, c := range cs {
			state := "not exported"
			if c.Exported {
				state = "EXPORTED"
				if c.Permission != "" {
					state += " (permission: " + c.Permission + ")"
				} else {
					state += " (no permission)"
				}
			}
			fmt.Fprintf(&b, "  %s  %s", state, c.Name)
			if c.Authorities != "" {
				fmt.Fprintf(&b, "  authorities=%s", c.Authorities)
			}
			if c.IntentFilters > 0 {
				fmt.Fprintf(&b, "  filters=%d", c.IntentFilters)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	writeComponents("Activities", info.Activities)
	writeComponents("Services", info.Services)
	writeComponents("Receivers", info.Receivers)
	writeComponents("Providers", info.Providers)

	if len(info.DeepLinks) > 0 {
		fmt.Fprintf(&b, "Deep links (%d)\n", len(info.DeepLinks))
		for _, l := range info.DeepLinks {
			verify := "unverified"
			if l.AutoVerify {
				verify = "autoVerify"
			}
			fmt.Fprintf(&b, "  %s://%s%s -> %s (%s)\n", l.Scheme, l.Host, deepLinkPath(l), l.Component, verify)
		}
		b.WriteString("\n")
	}

	// Permissions are numerous; list the dangerous ones inline and summarise
	// the rest, so the output stays readable on a package with 200 permissions.
	var dangerous []string
	for _, p := range info.Permissions {
		if isDangerousPermissionName(p.Name) {
			dangerous = append(dangerous, strings.TrimPrefix(p.Name, "android.permission."))
		}
	}
	fmt.Fprintf(&b, "Permissions: %d declared", len(info.Permissions))
	if len(dangerous) > 0 {
		fmt.Fprintf(&b, ", %d dangerous (%s)", len(dangerous), strings.Join(dangerous, ", "))
	}
	b.WriteString("\n\n")

	if len(info.NativeLibs) > 0 {
		fmt.Fprintf(&b, "Native libraries (%d): %s\n\n", len(info.NativeLibs), strings.Join(firstN(info.NativeLibs, 10), ", "))
	}
	if len(info.DexFiles) > 0 {
		fmt.Fprintf(&b, "Dex files: %s\n", strings.Join(info.DexFiles, ", "))
	}
	if withSecrets {
		fmt.Fprintf(&b, "Strings scanned: %d\n", info.StringsScanned)
	}
	b.WriteString("\n")

	if len(findings) == 0 {
		b.WriteString("Findings: none. The package declares no exported components without a permission, no insecure flags and no embedded credentials.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Findings (%d)\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(&b, "\n%d. [%s] %s\n", i+1, strings.ToUpper(f.Severity), f.Title)
		fmt.Fprintf(&b, "   class: %s\n", f.Class)
		fmt.Fprintf(&b, "   %s / %s\n", f.MASVS, f.MASTG)
		fmt.Fprintf(&b, "   %s\n", f.Detail)
		if f.Component != "" {
			fmt.Fprintf(&b, "   component: %s\n", f.Component)
		}
		if f.Evidence != "" {
			fmt.Fprintf(&b, "   evidence: %s\n", f.Evidence)
		}
	}
	b.WriteString("\nNothing above is proven exploitable by static analysis alone. An exported component needs a device and a hostile app to confirm reachability; a hardcoded credential needs a live call to confirm it is valid and what it grants. Report a finding only for what you can demonstrate, and cite the manifest element or file above as its evidence.\n")
	return b.String()
}

// deepLinkPath returns the deep-link path or prefix, whichever was declared.
func deepLinkPath(l mobile.DeepLink) string {
	if l.Path != "" {
		return l.Path
	}
	return l.PathPref
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string(nil), in[:n]...), fmt.Sprintf("... %d more", len(in)-n))
}

func orDashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// isDangerousPermissionName mirrors mobile's internal classification for the
// summary line. Kept local so the tool layer does not reach into unexported
// package state.
func isDangerousPermissionName(name string) bool {
	return mobile.IsDangerousPermission(name)
}
