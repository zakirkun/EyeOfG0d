package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeEmulatorClient struct {
	start         EmulatorStateSnapshot
	stop          EmulatorStateSnapshot
	status        EmulatorStateSnapshot
	starts, stops int
	statuses      int

	opResult   EmulatorOpResult
	installs   int
	launches   int
	logs       int
	packages   int
	installErr error

	lastAPK    []byte
	lastLaunch EmulatorLaunch
	lastTag    string
	lastLines  int
}

func (f *fakeEmulatorClient) Start(context.Context, string) (EmulatorStateSnapshot, error) {
	f.starts++
	return f.start, nil
}
func (f *fakeEmulatorClient) Stop(context.Context, string) (EmulatorStateSnapshot, error) {
	f.stops++
	return f.stop, nil
}
func (f *fakeEmulatorClient) Status(context.Context, string) (EmulatorStateSnapshot, error) {
	f.statuses++
	return f.status, nil
}
func (f *fakeEmulatorClient) Install(_ context.Context, _ string, apk []byte) (EmulatorOpResult, error) {
	f.installs++
	f.lastAPK = apk
	return f.opResult, f.installErr
}
func (f *fakeEmulatorClient) Launch(_ context.Context, _ string, l EmulatorLaunch) (EmulatorOpResult, error) {
	f.launches++
	f.lastLaunch = l
	return f.opResult, nil
}
func (f *fakeEmulatorClient) Logs(_ context.Context, _, tag string, lines int) (EmulatorOpResult, error) {
	f.logs++
	f.lastTag, f.lastLines = tag, lines
	return f.opResult, nil
}
func (f *fakeEmulatorClient) Packages(context.Context, string) (EmulatorOpResult, error) {
	f.packages++
	return f.opResult, nil
}

func TestSanitizeReason(t *testing.T) {
	if got := sanitizeReason("sidecar token leaked at /app/secret"); got != "emulator operation failed" {
		t.Fatalf("sanitized reason = %q", got)
	}
	if got := sanitizeReason("boot timed out"); got != "boot timed out" {
		t.Fatalf("safe reason = %q", got)
	}
}

// A dynamic operation is not a lifecycle call: installing a package transfers up
// to 256 MiB and then installs it, which takes far longer than a start/stop
// round trip. The delay here is deliberately longer than the old client-wide
// 4-second timeout, so this test fails if that timeout is ever restored as the
// governing budget for the dynamic path.
func TestInstallToleratesSlowSidecar(t *testing.T) {
	const delay = 5 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/install") {
			http.NotFound(w, r)
			return
		}
		time.Sleep(delay)
		_, _ = w.Write([]byte(`{"ok":true,"output":"package installed"}`))
	}))
	defer srv.Close()

	c := newSidecarClient(srv.URL)
	res, err := c.Install(context.Background(), "42", []byte("PK\x03\x04"))
	if err != nil {
		t.Fatalf("install against a slow sidecar failed: %v", err)
	}
	if !res.OK {
		t.Fatalf("install reported failure: %+v", res)
	}
}

// The same applies to the other operations, which are also not round trips.
func TestDynamicOpsTolerateSlowSidecar(t *testing.T) {
	const delay = 5 * time.Second
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		switch {
		case strings.HasSuffix(r.URL.Path, "/logs"):
			_, _ = w.Write([]byte(`{"ok":true,"output":"I/ActivityManager: start proc"}`))
		case strings.HasSuffix(r.URL.Path, "/launch"):
			_, _ = w.Write([]byte(`{"ok":true,"output":"Starting: Intent"}`))
		case strings.HasSuffix(r.URL.Path, "/packages"):
			_, _ = w.Write([]byte(`{"ok":true,"output":"package:com.target.app"}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()

	c := newSidecarClient(srv.URL)
	ctx := context.Background()

	// Concurrent, so the test costs one delay rather than three.
	var wg sync.WaitGroup
	errs := make([]error, 3)
	oks := make([]bool, 3)
	wg.Add(3)
	go func() { defer wg.Done(); r, e := c.Launch(ctx, "42", EmulatorLaunch{Component: "a.b/.C"}); errs[0], oks[0] = e, r.OK }()
	go func() { defer wg.Done(); r, e := c.Logs(ctx, "42", "", 200); errs[1], oks[1] = e, r.OK }()
	go func() { defer wg.Done(); r, e := c.Packages(ctx, "42"); errs[2], oks[2] = e, r.OK }()
	wg.Wait()

	for i, name := range []string{"launch", "logs", "packages"} {
		if errs[i] != nil || !oks[i] {
			t.Fatalf("%s against a slow sidecar: ok=%v err=%v", name, oks[i], errs[i])
		}
	}
}

// Lifecycle calls keep a tight budget: a status poll must not hang for minutes
// just because the dynamic path is allowed to.
func TestLifecycleCallsUseShortTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	c := newSidecarClient(srv.URL)
	start := time.Now()
	_, err := c.Status(context.Background(), "42")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("status against an unresponsive sidecar returned no error")
	}
	if elapsed > lifecycleTimeout+3*time.Second {
		t.Fatalf("status waited %s, longer than the lifecycle budget", elapsed)
	}
}

func TestEmulatorLifecycleIdempotenceWithFakeSidecar(t *testing.T) {
	fake := &fakeEmulatorClient{start: EmulatorStateSnapshot{State: EmulatorReady, Progress: 100}, stop: EmulatorStateSnapshot{State: EmulatorStopped}}
	e := &Emulator{root: t.TempDir(), enabled: true, client: fake, states: map[string]EmulatorStateSnapshot{}}
	e.capable = func() (EmulatorState, string) { return EmulatorStarting, "" }
	// The test does not depend on the host's KVM; replace the host capability gate
	// by asserting the persisted transition helpers and idempotence directly.
	task := &Task{ID: "42"}
	e.states[task.ID] = EmulatorStateSnapshot{TaskID: task.ID, State: EmulatorStopped}
	got, err := e.start(context.Background(), task)
	if err != nil || got.State != EmulatorReady || fake.starts != 1 {
		t.Fatalf("start = %+v, %v, calls=%d", got, err, fake.starts)
	}
	got, err = e.start(context.Background(), task)
	if err != nil || got.State != EmulatorReady || fake.starts != 1 {
		t.Fatalf("idempotent start = %+v, %v, calls=%d", got, err, fake.starts)
	}
	got, err = e.stop(context.Background(), task)
	if err != nil || got.State != EmulatorStopped || fake.stops != 1 {
		t.Fatalf("stop = %+v, %v, calls=%d", got, err, fake.stops)
	}
	got, err = e.stop(context.Background(), task)
	if err != nil || got.State != EmulatorStopped || fake.stops != 1 {
		t.Fatalf("idempotent stop = %+v, %v, calls=%d", got, err, fake.stops)
	}
}

func TestEmulatorDynamicOpsRefusedUntilReady(t *testing.T) {
	fake := &fakeEmulatorClient{opResult: EmulatorOpResult{OK: true, Output: "ok"}}
	e := &Emulator{root: t.TempDir(), enabled: true, client: fake, states: map[string]EmulatorStateSnapshot{}}
	e.capable = func() (EmulatorState, string) { return EmulatorStarting, "" }

	// No runtime yet: every dynamic operation must refuse and must not reach the
	// sidecar. This is the property that stops a "prove it without a device" bug.
	if e.Ready("42") {
		t.Fatal("Ready reported true with no emulator")
	}
	if _, err := e.Install(context.Background(), "42", []byte("PK\x03\x04")); err == nil {
		t.Fatal("install succeeded without a ready emulator")
	}
	if _, err := e.Launch(context.Background(), "42", EmulatorLaunch{Component: "a.b/.C"}); err == nil {
		t.Fatal("launch succeeded without a ready emulator")
	}
	if _, err := e.Logs(context.Background(), "42", "", 10); err == nil {
		t.Fatal("logs succeeded without a ready emulator")
	}
	if _, err := e.Packages(context.Background(), "42"); err == nil {
		t.Fatal("packages succeeded without a ready emulator")
	}

	if fake.installs+fake.launches+fake.logs+fake.packages != 0 {
		t.Fatalf("sidecar was called while not ready: install=%d launch=%d logs=%d packages=%d",
			fake.installs, fake.launches, fake.logs, fake.packages)
	}
}

func TestEmulatorDynamicOpsAllowedWhenReady(t *testing.T) {
	fake := &fakeEmulatorClient{opResult: EmulatorOpResult{OK: true, Output: "Success"}}
	e := &Emulator{root: t.TempDir(), enabled: true, client: fake, states: map[string]EmulatorStateSnapshot{}}
	e.capable = func() (EmulatorState, string) { return EmulatorStarting, "" }
	e.states["42"] = EmulatorStateSnapshot{TaskID: "42", State: EmulatorReady, Progress: 100}

	if !e.Ready("42") {
		t.Fatal("Ready reported false for a ready task")
	}

	apk := []byte("PK\x03\x04payload")
	res, err := e.Install(context.Background(), "42", apk)
	if err != nil || !res.OK {
		t.Fatalf("install = %+v, %v", res, err)
	}
	if string(fake.lastAPK) != string(apk) {
		t.Fatal("install did not forward the package bytes")
	}

	res, err = e.Launch(context.Background(), "42", EmulatorLaunch{
		Component: "com.target.app/.Admin",
		Extras:    map[string]string{"url": "https://attacker.test"},
	})
	if err != nil || !res.OK {
		t.Fatalf("launch = %+v, %v", res, err)
	}
	if fake.lastLaunch.Component != "com.target.app/.Admin" {
		t.Fatalf("launch component = %q", fake.lastLaunch.Component)
	}

	res, err = e.Logs(context.Background(), "42", "ActivityManager", 50)
	if err != nil || !res.OK {
		t.Fatalf("logs = %+v, %v", res, err)
	}
	if fake.lastTag != "ActivityManager" || fake.lastLines != 50 {
		t.Fatalf("logs args = %q/%d", fake.lastTag, fake.lastLines)
	}

	if _, err = e.Packages(context.Background(), "42"); err != nil {
		t.Fatalf("packages: %v", err)
	}
}

func TestEmulatorReadyIsFalseForOtherTask(t *testing.T) {
	fake := &fakeEmulatorClient{}
	e := &Emulator{root: t.TempDir(), enabled: true, client: fake, states: map[string]EmulatorStateSnapshot{}}
	e.capable = func() (EmulatorState, string) { return EmulatorStarting, "" }
	e.states["42"] = EmulatorStateSnapshot{TaskID: "42", State: EmulatorReady}

	// Readiness is per task; task 43 must not inherit task 42's emulator.
	if e.Ready("43") {
		t.Fatal("Ready leaked across tasks")
	}
}

func TestEmulatorReadyIsFalseWhenDisabled(t *testing.T) {
	e := &Emulator{root: t.TempDir(), enabled: false, client: &fakeEmulatorClient{}, states: map[string]EmulatorStateSnapshot{"42": {TaskID: "42", State: EmulatorReady}}}
	if e.Ready("42") {
		t.Fatal("Ready reported true while the emulator is disabled")
	}
}

func TestEmulatorLogsBoundsLineCount(t *testing.T) {
	fake := &fakeEmulatorClient{opResult: EmulatorOpResult{OK: true}}
	e := &Emulator{root: t.TempDir(), enabled: true, client: fake, states: map[string]EmulatorStateSnapshot{}}
	e.capable = func() (EmulatorState, string) { return EmulatorStarting, "" }
	e.states["42"] = EmulatorStateSnapshot{TaskID: "42", State: EmulatorReady}

	if _, err := e.Logs(context.Background(), "42", "", 999999); err != nil {
		t.Fatal(err)
	}
	if fake.lastLines > 2000 {
		t.Fatalf("unbounded log request forwarded: %d", fake.lastLines)
	}
}

func TestEmulatorSnapshotReconcilesActiveState(t *testing.T) {
	e := &Emulator{root: t.TempDir(), states: map[string]EmulatorStateSnapshot{}}
	e.snapshot(EmulatorStateSnapshot{TaskID: "7", State: EmulatorReady, UpdatedAt: time.Now()})
	e.states = map[string]EmulatorStateSnapshot{}
	got := e.load("7")
	if got.State != EmulatorFailed || got.Reason == "" {
		t.Fatalf("stale state = %+v", got)
	}
}
