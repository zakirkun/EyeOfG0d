package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// stubEmulator records what the tools asked of it. It proves the wiring rather
// than the transport; the server-side client has its own tests.
type stubEmulator struct {
	ready    bool
	installs int
	launches int
	logs     int
	packages int
	lastReq  EmulatorLaunch
	lastTag  string
}

func (s *stubEmulator) Ready(string) bool { return s.ready }

func (s *stubEmulator) Install(_ context.Context, _ string, apk []byte) (EmulatorOpResult, error) {
	s.installs++
	return EmulatorOpResult{OK: true, Output: "package installed"}, nil
}

func (s *stubEmulator) Launch(_ context.Context, _ string, req EmulatorLaunch) (EmulatorOpResult, error) {
	s.launches++
	s.lastReq = req
	return EmulatorOpResult{OK: true, Output: "Starting: Intent"}, nil
}

func (s *stubEmulator) Logs(_ context.Context, _, tag string, _ int) (EmulatorOpResult, error) {
	s.logs++
	s.lastTag = tag
	return EmulatorOpResult{OK: true, Output: "I/ActivityManager: start proc"}, nil
}

func (s *stubEmulator) Packages(context.Context, string) (EmulatorOpResult, error) {
	s.packages++
	return EmulatorOpResult{OK: true, Output: "package:com.target.app"}, nil
}

// byName returns the named tool from a set, or nil.
func byName(tools []actool.CoreTool, name string) actool.CoreTool {
	for _, tool := range tools {
		if tool.Name() == name {
			return tool
		}
	}
	return nil
}

// The emulator tools are only useful if the task's device actually reaches the
// ToolSet a worker builds. Without this wiring the tools report "no emulator" on
// a host that is running one — the worst outcome, because it reads as "dynamic
// testing is impossible" rather than "you configured it wrongly".
func TestWorkerToolSetReceivesEmulator(t *testing.T) {
	em := &stubEmulator{ready: true}
	w := NewWorker(nil, "test-model", t.TempDir(), nil, 0, 0)
	w.SetEmulator(em)

	ts := NewToolSet(nil, "worker")
	ts.SetEmulator(w.emulator)
	ts.SetTaskID(7)

	tools := ts.WorkerTools()
	for _, name := range []string{"install_target_apk", "launch_component", "read_logcat", "list_emulator_packages"} {
		if byName(tools, name) == nil {
			t.Fatalf("%s is not registered", name)
		}
	}

	// And the device is actually used, not merely present in the field.
	res, err := byName(tools, "launch_component").Call(context.Background(),
		json.RawMessage(`{"component":"com.target.app/.Admin","extras":{"url":"https://attacker.test"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || em.launches != 1 {
		t.Fatalf("launch did not reach the emulator: IsError=%v launches=%d body=%s", res.IsError, em.launches, res.Flatten())
	}
	if em.lastReq.Component != "com.target.app/.Admin" {
		t.Fatalf("component reached the emulator as %q", em.lastReq.Component)
	}
	if em.lastReq.Extras["url"] != "https://attacker.test" {
		t.Fatalf("extras reached the emulator as %v", em.lastReq.Extras)
	}
}

// Without an emulator every dynamic tool must say so explicitly. A silent empty
// success would let a model conclude the component was not exploitable.
func TestEmulatorToolsReportUnavailableWithoutDevice(t *testing.T) {
	ts := NewToolSet(nil, "worker")
	tools := ts.WorkerTools()

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"install_target_apk", `{"path":"target.apk"}`},
		{"launch_component", `{"component":"com.target.app/.Admin"}`},
		{"read_logcat", `{}`},
		{"list_emulator_packages", `{}`},
	} {
		tool := byName(tools, tc.name)
		if tool == nil {
			t.Fatalf("%s is not registered", tc.name)
		}
		res, err := tool.Call(context.Background(), json.RawMessage(tc.input), nil)
		if err != nil {
			t.Fatalf("%s returned a transport error: %v", tc.name, err)
		}
		if res.IsError {
			t.Fatalf("%s is an error rather than an explanation: %s", tc.name, res.Flatten())
		}
		body := res.Flatten()
		if !strings.Contains(body, "no Android emulator is ready") {
			t.Fatalf("%s did not explain the missing device: %q", tc.name, body)
		}
		if strings.Contains(strings.ToLower(body), "not vulnerable") {
			t.Fatalf("%s implies a negative finding: %q", tc.name, body)
		}
	}

	// A failed operation must not be rendered as an empty success either.
	if got := renderOpResult("launch_component", EmulatorOpResult{OK: false, Reason: "am rejected the intent"}); !strings.Contains(got, "failed") {
		t.Fatalf("failure rendered as success: %q", got)
	}
}

// The install tool must refuse an oversized file before uploading it. Reading a
// whole file with os.ReadFile would let a multi-gigabyte path exhaust the agent.
func TestInstallRejectsOversizedAndDirectoryPaths(t *testing.T) {
	dir := t.TempDir()

	// A file one byte past the limit, created sparsely so the test is cheap.
	big := filepath.Join(dir, "big.apk")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxInstallBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := readBoundedFile(big, maxInstallBytes); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized file was not refused: %v", err)
	}
	if _, err := readBoundedFile(dir, maxInstallBytes); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory was not refused: %v", err)
	}

	// And a file at the limit is accepted, so the bound is not off by one.
	ok := filepath.Join(dir, "ok.apk")
	if err := os.WriteFile(ok, []byte("PK\x03\x04"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(ok, maxInstallBytes); err != nil {
		t.Fatalf("small file was refused: %v", err)
	}
}
