package mobile

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildAPK writes a minimal APK whose manifest is plain XML, so the analysis
// path is exercised end to end without needing a real Android build toolchain.
// The structure (zip + AndroidManifest.xml) is exactly what a device receives.
func buildAPK(t *testing.T, manifest string, extra map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}
	if _, err := w.Write([]byte(manifest)); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	for name, data := range extra {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return path
}

const insecureManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.insecure" versionName="1.2.3" versionCode="42">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="24"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:debuggable="true" android:allowBackup="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="myapp" android:host="open"/>
      </intent-filter>
    </activity>
    <activity android:name=".AdminActivity" android:exported="true"/>
    <service android:name=".SyncService" android:exported="true"/>
    <receiver android:name=".PushReceiver" android:exported="true"
        android:permission="com.example.PUSH"/>
    <provider android:name=".FileProvider"
        android:authorities="com.example.files"
        android:exported="true" android:grantUriPermissions="true"/>
  </application>
</manifest>`

func TestAnalyseInsecureManifest(t *testing.T) {
	path := buildAPK(t, insecureManifest, nil)
	info, err := Analyse(path)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if info.PackageName != "com.example.insecure" {
		t.Errorf("PackageName = %q", info.PackageName)
	}
	if info.VersionName != "1.2.3" || info.VersionCode != "42" {
		t.Errorf("version = %q/%q", info.VersionName, info.VersionCode)
	}
	if !info.Debuggable || !info.DebugFlagPresent {
		t.Error("debuggable not detected")
	}
	if !info.AllowBackup {
		t.Error("allowBackup not detected")
	}
	if !info.UsesCleartext {
		t.Error("usesCleartextTraffic not detected")
	}
	if info.TargetSDK != "24" {
		t.Errorf("TargetSDK = %q", info.TargetSDK)
	}

	// The launcher activity has an intent filter and no explicit exported, so
	// the platform default makes it exported.
	var main *Component
	for i := range info.Activities {
		if strings.HasSuffix(info.Activities[i].Name, "MainActivity") {
			main = &info.Activities[i]
		}
	}
	if main == nil {
		t.Fatal("MainActivity not collected")
	}
	if !main.Exported || main.ExportedPresent {
		t.Errorf("MainActivity exported=%v present=%v, want exported by default", main.Exported, main.ExportedPresent)
	}

	// The receiver declares a permission, so it must not be counted as
	// unprotected even though it is exported.
	for _, c := range info.ExportedNoPerms {
		if strings.HasSuffix(c.Name, "PushReceiver") {
			t.Error("receiver with a permission was counted as unprotected")
		}
	}

	// Deep link on a custom scheme must be collected.
	if len(info.DeepLinks) != 1 || info.DeepLinks[0].Scheme != "myapp" {
		t.Errorf("DeepLinks = %+v", info.DeepLinks)
	}
	if len(info.CustomSchemes) != 1 || info.CustomSchemes[0] != "myapp" {
		t.Errorf("CustomSchemes = %v", info.CustomSchemes)
	}
}

func TestEvaluateReportsExpectedClasses(t *testing.T) {
	path := buildAPK(t, insecureManifest, nil)
	info, err := Analyse(path)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	findings := Evaluate(info)

	got := map[string]int{}
	for _, f := range findings {
		got[f.Class]++
	}
	for _, want := range []string{
		"debuggable_app",
		"backup_enabled",
		"cleartext_traffic",
		"exported_component",
		"overpermissive_provider",
		"insecure_deep_link",
		"unsigned_apk",
	} {
		if got[want] == 0 {
			t.Errorf("missing finding class %q (got %v)", want, got)
		}
	}
	if got["weak_signing_scheme"] != 0 {
		t.Error("weak_signing_scheme reported for an unsigned package")
	}

	// Every finding must carry the provenance the report needs.
	for _, f := range findings {
		if f.Class == "" || f.Title == "" || f.Severity == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
		if f.MASVS == "" || f.MASTG == "" {
			t.Errorf("finding %q missing MASVS/MASTG mapping", f.Class)
		}
		if f.Class != "native_code_present" && f.Class != "no_code_obfuscation" && f.Evidence == "" {
			t.Errorf("finding %q has no evidence", f.Class)
		}
	}
}

// A clean package must not produce findings. This is the false-positive guard:
// a manifest with every risky flag set explicitly to its safe value.
func TestEvaluateCleanPackageHasNoFindings(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.clean" versionName="2.0" versionCode="7">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34"/>
  <application android:debuggable="false" android:allowBackup="false"
      android:usesCleartextTraffic="false">
    <activity android:name=".MainActivity" android:exported="false"/>
  </application>
</manifest>`
	path := buildAPK(t, manifest, nil)
	info, err := Analyse(path)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	for _, f := range Evaluate(info) {
		// Unsigned is real for this fixture (no signing material), so only
		// flag findings the manifest itself should not have produced.
		if f.Class == "unsigned_apk" {
			continue
		}
		t.Errorf("unexpected finding on a clean manifest: %s (%s)", f.Class, f.Evidence)
	}
}

func TestScanSecretsRedactsValue(t *testing.T) {
	// A Google API key shape, which the scanner must catch and redact.
	const key = "AIzaSyD-1234567890abcdefghijklmnopqrstu"
	text := "BASE_URL=https://api.example.com\nAPI_KEY=" + key + "\n"
	findings := ScanSecrets(text, "classes.dex")
	if len(findings) == 0 {
		t.Fatal("no secret found")
	}
	f := findings[0]
	if f.Class != "hardcoded_secret" {
		t.Errorf("class = %q", f.Class)
	}
	if strings.Contains(f.Evidence, key) {
		t.Error("evidence contains the secret in full; it must be redacted")
	}
	if !strings.Contains(f.Evidence, "classes.dex") {
		t.Errorf("evidence lost its origin: %q", f.Evidence)
	}
}

func TestScanSecretsIgnoresOrdinaryText(t *testing.T) {
	text := "This is an ordinary log line with no credentials at all.\n"
	if got := ScanSecrets(text, "classes.dex"); len(got) != 0 {
		t.Errorf("false positive on ordinary text: %+v", got)
	}
}

func TestSdkLessThan(t *testing.T) {
	cases := []struct {
		in    string
		level int
		want  bool
	}{
		{"24", 28, true},
		{"28", 28, false},
		{"34", 28, false},
		{"", 28, false},
		{"Tiramisu", 28, false}, // a codename cannot be ordered
	}
	for _, c := range cases {
		if got := sdkLessThan(c.in, c.level); got != c.want {
			t.Errorf("sdkLessThan(%q, %d) = %v, want %v", c.in, c.level, got, c.want)
		}
	}
}

func TestAnalyseRejectsNonZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not.apk")
	if err := os.WriteFile(path, []byte("this is not a zip file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Analyse(path); err == nil {
		t.Fatal("expected an error for a non-zip file")
	}
}

func TestAnalyseRequiresManifest(t *testing.T) {
	path := buildAPK(t, "", map[string][]byte{"classes.dex": []byte("dex\n035")})
	// Remove the manifest by building an archive without one instead.
	dir := t.TempDir()
	p2 := filepath.Join(dir, "nomanifest.apk")
	f, _ := os.Create(p2)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("classes.dex")
	w.Write([]byte("dex\n035\x00"))
	zw.Close()
	f.Close()

	if _, err := Analyse(p2); err == nil || !strings.Contains(err.Error(), "AndroidManifest") {
		t.Fatalf("expected a missing-manifest error, got %v", err)
	}
	_ = path
}

func TestParseAXMLRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("<?xml"),
		{0x03, 0x00, 0x08, 0x00}, // header only, no chunks
	} {
		if _, err := ParseAXML(in); err == nil {
			t.Errorf("ParseAXML(%x) accepted invalid input", in)
		}
	}
}

// The fingerprint premise depends on stable, comparable class tokens. Padding
// and case must not change what a finding groups as.
func TestFindingClassesAreStableTokens(t *testing.T) {
	path := buildAPK(t, insecureManifest, nil)
	info, _ := Analyse(path)
	for _, f := range Evaluate(info) {
		if f.Class != strings.ToLower(f.Class) {
			t.Errorf("class %q is not lowercase", f.Class)
		}
		if strings.ContainsAny(f.Class, " -\t") {
			t.Errorf("class %q contains whitespace or dashes, which the diff would treat as distinct", f.Class)
		}
	}
}
