package mobile

import (
	"strings"
	"testing"
)

// everyPurposeRequest returns one valid request per supported purpose, so the
// table below proves every template builds rather than only the easy ones.
func everyPurposeRequest() map[string]FridaRequest {
	pkg := "com.example.target"
	return map[string]FridaRequest{
		FridaSSLPinning:      {Purpose: FridaSSLPinning, Package: pkg},
		FridaRootDetection:   {Purpose: FridaRootDetection, Package: pkg},
		FridaAntiDebug:       {Purpose: FridaAntiDebug, Package: pkg},
		FridaMethodTrace:     {Purpose: FridaMethodTrace, Package: pkg, Class: "com.example.target.LoginActivity", Method: "handleIntent"},
		FridaClassEnum:       {Purpose: FridaClassEnum, Package: pkg, Pattern: "crypto"},
		FridaKeystoreDump:    {Purpose: FridaKeystoreDump, Package: pkg},
		FridaSharedPrefs:     {Purpose: FridaSharedPrefs, Package: pkg},
		FridaIntentMonitor:   {Purpose: FridaIntentMonitor, Package: pkg},
		FridaWebViewHook:     {Purpose: FridaWebViewHook, Package: pkg},
		FridaCryptoHook:      {Purpose: FridaCryptoHook, Package: pkg},
		FridaBiometricBypass: {Purpose: FridaBiometricBypass, Package: pkg},
		FridaNativeHook:      {Purpose: FridaNativeHook, Package: pkg, Module: "libssl.so", Symbol: "SSL_verify_cert_chain"},
	}
}

// The purpose list and the fixture must agree: a purpose added to one without
// the other would silently ship untested.
func TestFridaPurposesMatchFixtures(t *testing.T) {
	purposes := FridaPurposes()
	fixtures := everyPurposeRequest()

	if len(purposes) != len(fixtures) {
		t.Fatalf("%d purposes but %d fixtures", len(purposes), len(fixtures))
	}
	for _, p := range purposes {
		if _, ok := fixtures[p]; !ok {
			t.Errorf("purpose %q has no test fixture", p)
		}
	}
	for p := range fixtures {
		found := false
		for _, q := range purposes {
			if p == q {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fixture %q is not in FridaPurposes", p)
		}
	}
}

// Every template must build, carry a non-empty script, and leave no placeholder
// behind. This is the guard against a template added with a typo'd variable.
func TestBuildFridaScriptEveryPurpose(t *testing.T) {
	for purpose, req := range everyPurposeRequest() {
		script, err := BuildFridaScript(req)
		if err != nil {
			t.Errorf("%s: BuildFridaScript: %v", purpose, err)
			continue
		}
		if script.Purpose != purpose {
			t.Errorf("%s: Purpose = %q", purpose, script.Purpose)
		}
		if strings.TrimSpace(script.Title) == "" {
			t.Errorf("%s: empty title", purpose)
		}
		if strings.TrimSpace(script.Description) == "" {
			t.Errorf("%s: empty description", purpose)
		}
		if strings.TrimSpace(script.Script) == "" {
			t.Errorf("%s: empty script", purpose)
		}
		if strings.Contains(script.Script, "{{") {
			t.Errorf("%s: script has an unsubstituted placeholder", purpose)
		}
		if strings.TrimSpace(script.RunCommand) == "" {
			t.Errorf("%s: empty run command", purpose)
		}
		// The run command must name the package, not a placeholder.
		if !strings.Contains(script.RunCommand, req.Package) {
			t.Errorf("%s: run command does not name the package: %q", purpose, script.RunCommand)
		}
	}
}

// Every hook must run inside Java.perform or be a native Interceptor: a
// Java.use call at top level throws before the runtime is attached.
func TestBuildFridaScriptJavaTemplatesUseJavaPerform(t *testing.T) {
	for purpose, req := range everyPurposeRequest() {
		script, err := BuildFridaScript(req)
		if err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
		if purpose == FridaNativeHook {
			// Native hook uses Interceptor, not the Java bridge. The template
			// mentions Java.perform in a comment, so assert on the call form.
			if strings.Contains(script.Script, "Java.perform(function") {
				t.Errorf("%s: native hook should not call Java.perform", purpose)
			}
			if !strings.Contains(script.Script, "Interceptor.attach") {
				t.Errorf("%s: native hook does not attach an interceptor", purpose)
			}
			continue
		}
		if !strings.Contains(script.Script, "Java.perform(function") {
			t.Errorf("%s: script does not call Java.perform", purpose)
		}
		if strings.Contains(script.Script, "Java.use") && !strings.Contains(script.Script, "Java.perform(function") {
			t.Errorf("%s: Java.use outside Java.perform", purpose)
		}
	}
}

// A missing required parameter must be a build error. Attaching a hook that
// targets nothing looks exactly like a target that is not vulnerable, so the
// builder has to refuse rather than emit a no-op.
func TestBuildFridaScriptRequiresParameters(t *testing.T) {
	cases := []struct {
		name string
		req  FridaRequest
		want string // substring expected in the error
	}{
		{
			name: "method_trace without class",
			req:  FridaRequest{Purpose: FridaMethodTrace, Method: "doIt"},
			want: "class",
		},
		{
			name: "method_trace without method",
			req:  FridaRequest{Purpose: FridaMethodTrace, Class: "com.example.Foo"},
			want: "method",
		},
		{
			name: "native_hook without module",
			req:  FridaRequest{Purpose: FridaNativeHook, Symbol: "SSL_verify_cert_chain"},
			want: "module",
		},
		{
			name: "native_hook without symbol",
			req:  FridaRequest{Purpose: FridaNativeHook, Module: "libssl.so"},
			want: "symbol",
		},
		{
			name: "empty purpose",
			req:  FridaRequest{},
			want: "purpose is required",
		},
		{
			name: "unknown purpose",
			req:  FridaRequest{Purpose: "magic"},
			want: "unsupported purpose",
		},
	}
	for _, c := range cases {
		_, err := BuildFridaScript(c.req)
		if err == nil {
			t.Errorf("%s: expected an error, got a script", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

// A quote or backslash in a substituted value would break out of the JS string
// literal it lands in, turning a parameter into code. That must be refused.
func TestSubstituteFridaRejectsInjection(t *testing.T) {
	tmpl := `var x = '{{value}}';`
	bad := []string{
		`a'b`,
		`a"b`,
		`a\b`,
		"a\nb",
		"a\rb",
	}
	for _, v := range bad {
		if _, err := substituteFrida(tmpl, map[string]string{"value": v}); err == nil {
			t.Errorf("substituteFrida accepted %q", v)
		}
	}

	// A plain class name is accepted, dots and dollar signs included.
	if got, err := substituteFrida(tmpl, map[string]string{"value": "com.example.Outer$Inner"}); err != nil {
		t.Errorf("substituteFrida rejected a valid class name: %v", err)
	} else if !strings.Contains(got, "com.example.Outer$Inner") {
		t.Errorf("substitution lost the value: %q", got)
	}
}

func TestSubstituteFridaRejectsEmptyRequired(t *testing.T) {
	if _, err := substituteFrida(`Java.use('{{class}}')`, map[string]string{"class": ""}); err == nil {
		t.Error("expected an error for an empty required placeholder")
	}
	if _, err := substituteFrida(`Java.use('{{class}}')`, map[string]string{"class": "   "}); err == nil {
		t.Error("expected an error for a whitespace-only placeholder")
	}
}

// Optional placeholders exist for filters, where absence is meaningful.
func TestSubstituteFridaOptionalPlaceholder(t *testing.T) {
	got, err := substituteFrida(`var p = '{{?pattern}}'`, map[string]string{"pattern": ""})
	if err != nil {
		t.Fatalf("optional placeholder with an empty value failed: %v", err)
	}
	if got != `var p = ''` {
		t.Errorf("got %q", got)
	}

	got, err = substituteFrida(`var p = '{{?pattern}}'`, map[string]string{"pattern": "crypto"})
	if err != nil {
		t.Fatalf("optional placeholder with a value failed: %v", err)
	}
	if !strings.Contains(got, "crypto") {
		t.Errorf("got %q", got)
	}

	// The injection check still applies to optional placeholders.
	if _, err := substituteFrida(`var p = '{{?pattern}}'`, map[string]string{"pattern": `a'b`}); err == nil {
		t.Error("optional placeholder accepted a quote")
	}
}

// class_enum is the one purpose whose parameter is genuinely optional: it lists
// everything when unfiltered.
func TestBuildFridaClassEnumWithoutPattern(t *testing.T) {
	script, err := BuildFridaScript(FridaRequest{Purpose: FridaClassEnum})
	if err != nil {
		t.Fatalf("class_enum without a pattern must build: %v", err)
	}
	if strings.Contains(script.Script, "{{") {
		t.Error("unsubstituted placeholder")
	}
	// Without a package the run command must still be usable, so it carries a
	// placeholder marker rather than an empty -f argument.
	if strings.Contains(script.RunCommand, "-f  ") {
		t.Errorf("run command has an empty package slot: %q", script.RunCommand)
	}
}

// The method-trace template hooks every overload; that is the whole point of it.
func TestMethodTraceHooksAllOverloads(t *testing.T) {
	script, err := BuildFridaScript(FridaRequest{
		Purpose: FridaMethodTrace,
		Package: "com.example.target",
		Class:   "com.example.target.LoginActivity",
		Method:  "handleIntent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script.Script, ".overloads") {
		t.Error("method_trace does not iterate overloads")
	}
	if !strings.Contains(script.Script, "com.example.target.LoginActivity") {
		t.Error("method_trace did not substitute the class")
	}
	if !strings.Contains(script.Script, "handleIntent") {
		t.Error("method_trace did not substitute the method")
	}
}

func TestIntentMonitorPreservesOnNewIntentOverload(t *testing.T) {
	script, err := BuildFridaScript(FridaRequest{Purpose: FridaIntentMonitor})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script.Script, "var onNewIntent = Activity2.onNewIntent.overload('android.content.Intent');") {
		t.Error("onNewIntent hook does not capture the original overload")
	}
	if !strings.Contains(script.Script, "return onNewIntent.call(this, i);") {
		t.Error("onNewIntent hook does not call the original overload")
	}
	if strings.Contains(script.Script, "return this.onNewIntent(i);") {
		t.Error("onNewIntent hook recursively calls the replacement")
	}
}

func TestCryptoHookDigestsOnce(t *testing.T) {
	script, err := BuildFridaScript(FridaRequest{Purpose: FridaCryptoHook})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(script.Script, "this.digest(input)") != 1 {
		t.Errorf("MessageDigest.digest called %d times, want 1", strings.Count(script.Script, "this.digest(input)"))
	}
}

// The native hook must wait for the module: hooking before it loads silently
// does nothing, which a model reading the script would never notice.
func TestNativeHookWaitsForModule(t *testing.T) {
	script, err := BuildFridaScript(FridaRequest{
		Purpose: FridaNativeHook,
		Package: "com.example.target",
		Module:  "libssl.so",
		Symbol:  "SSL_verify_cert_chain",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"findModuleByName", "libssl.so", "SSL_verify_cert_chain", "setInterval"} {
		if !strings.Contains(script.Script, want) {
			t.Errorf("native hook script missing %q", want)
		}
	}
	if !strings.Contains(script.Script, "try {\n     addr = Module.getExportByName(moduleName, symbolName);") {
		t.Error("native hook does not guard export lookup")
	}
	if !strings.Contains(script.Script, "export lookup failed") {
		t.Error("native hook does not report export lookup failures")
	}
}

func TestMethodTraceRejectsInvalidJavaIdentifiers(t *testing.T) {
	cases := []struct {
		name   string
		class  string
		method string
	}{
		{name: "class injection", class: "com.example.Foo;evil()", method: "handleIntent"},
		{name: "method injection", class: "com.example.Foo", method: "handleIntent;evil()"},
		{name: "class segment starts digit", class: "com.example.123Foo", method: "handleIntent"},
	}
	for _, tc := range cases {
		_, err := BuildFridaScript(FridaRequest{
			Purpose: FridaMethodTrace,
			Class:   tc.class,
			Method:  tc.method,
		})
		if err == nil {
			t.Errorf("%s: expected invalid Java identifier error", tc.name)
		}
	}
}

// Every script must carry its caveats. A pinning bypass presented without the
// "this changes what you observe" note is an invitation to over-report.
func TestEveryFridaScriptStatesItsCaveats(t *testing.T) {
	for purpose, req := range everyPurposeRequest() {
		script, err := BuildFridaScript(req)
		if err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
		if len(script.Requirements) == 0 {
			t.Errorf("%s: no requirements stated", purpose)
		}
		if len(script.Warnings) == 0 {
			t.Errorf("%s: no caveats stated", purpose)
		}
	}
}

func TestFridaScriptMarkdownIsComplete(t *testing.T) {
	script, err := BuildFridaScript(everyPurposeRequest()[FridaSSLPinning])
	if err != nil {
		t.Fatal(err)
	}
	md := FridaScriptMarkdown(script)
	for _, want := range []string{
		script.Title,
		script.Description,
		script.RunCommand,
		"```javascript",
		"Requirements",
		"Caveats",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if FridaScriptMarkdown(nil) != "" {
		t.Error("FridaScriptMarkdown(nil) should be empty")
	}
}

// A script must never claim a vulnerability was proven: the caveats carry the
// distinction between "the control is bypassable" and "the app is exploitable".
func TestFridaCaveatsDistinguishBypassFromExploit(t *testing.T) {
	ssl, err := BuildFridaScript(FridaRequest{Purpose: FridaSSLPinning, Package: "com.example.target"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.ToLower(strings.Join(ssl.Warnings, " "))
	if !strings.Contains(joined, "not that") && !strings.Contains(joined, "not that the app") {
		// The warning wording is deliberately explicit about what a bypass proves.
		if !strings.Contains(joined, "proves the pinning is bypassable") {
			t.Errorf("ssl_pinning caveats do not separate bypass from exposure: %v", ssl.Warnings)
		}
	}

	bio, err := BuildFridaScript(FridaRequest{Purpose: FridaBiometricBypass, Package: "com.example.target"})
	if err != nil {
		t.Fatal(err)
	}
	bioJoined := strings.ToLower(strings.Join(bio.Warnings, " "))
	if !strings.Contains(bioJoined, "server") {
		t.Error("biometric caveats do not mention that a server-side requirement still fails")
	}
}
