package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/mobile"
	actool "github.com/Autumn-27/norma/tool"
)

// buildFridaScript is the agent-facing entry point for Frida instrumentation.
//
// It is read-only and deterministic: it renders a known-good script for a stated
// purpose and returns it with its run command and caveats. Nothing is executed
// and nothing is written, so it is safe to give to every agent.
//
// The tool exists because a model writing Frida JavaScript from memory produces
// scripts that look right and hook nothing - a missing .overload(), a hook
// installed before Java.perform, the wrong OkHttp major version. On a live
// target that wastes an engagement slot and reads as "the control is not
// present", which is the one wrong conclusion instrumenting is meant to settle.
func (t *ToolSet) buildFridaScript() actool.CoreTool {
	return readTool(
		"build_frida_script",
		"Render a known-good Frida instrumentation script for a mobile engagement, parameterised by purpose. Returns the JavaScript, the exact run command, its runtime requirements and its caveats.\n\n"+
			"Purposes: "+strings.Join(mobile.FridaPurposes(), ", ")+".\n\n"+
			"Use it before instrumenting a live target, and save the script to the workspace rather than retyping it. It does not run anything and needs no device. The caveats it returns are part of the result: a pinning bypass proves the pinning is bypassable, not that the app's data is exposed, and reporting the difference is what separates a finding from a guess.",
		obj(map[string]any{
			"purpose": str("the instrumentation goal; one of: " + strings.Join(mobile.FridaPurposes(), ", ")),
			"package": str("the Android application id, e.g. com.example.app; used for the run command"),
			"class":   str("fully qualified class name; required for method_trace"),
			"method":  str("method name to hook; required for method_trace, hooks every overload"),
			"module":  str("native library name, e.g. libssl.so; required for native_hook"),
			"symbol":  str("exported native symbol, e.g. SSL_verify_cert_chain; required for native_hook"),
			"pattern": str("case-insensitive substring filter for class_enum; omit to list everything"),
		}, "purpose"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Purpose string `json:"purpose"`
				Package string `json:"package"`
				Class   string `json:"class"`
				Method  string `json:"method"`
				Module  string `json:"module"`
				Symbol  string `json:"symbol"`
				Pattern string `json:"pattern"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("invalid input: %v", err)), nil
			}

			script, err := mobile.BuildFridaScript(mobile.FridaRequest{
				Purpose: a.Purpose,
				Package: a.Package,
				Class:   a.Class,
				Method:  a.Method,
				Module:  a.Module,
				Symbol:  a.Symbol,
				Pattern: a.Pattern,
			})
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(mobile.FridaScriptMarkdown(script)), nil
		},
	)
}
