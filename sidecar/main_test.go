package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProcess is an emulator process stand-in whose exit is controllable.
type fakeProcess struct {
	once sync.Once
	done chan struct{}
	err  error
}

func newFakeProcess() *fakeProcess { return &fakeProcess{done: make(chan struct{})} }

func (p *fakeProcess) Done() <-chan struct{} { return p.done }
func (p *fakeProcess) Err() error            { return p.err }
func (p *fakeProcess) exit(err error)        { p.once.Do(func() { p.err = err; close(p.done) }) }
func (p *fakeProcess) Terminate() error      { p.exit(nil); return nil }
func (p *fakeProcess) Kill() error           { p.exit(nil); return nil }

// fakeDriver records order of operations and injects failures.
type fakeDriver struct {
	mu sync.Mutex

	kvmErr     error
	avdErr     error
	startErr   error
	readyErr   error
	readyBlock bool

	installErr error
	launchErr  error

	proc *fakeProcess

	kvmCalls    int
	createCalls int
	startCalls  int
	readyCalls  int
	shutdowns   int
	installs    int
	launches    int
	logCalls    int
	packageCalls int
	removed     []string
	reaps       int

	installPath string
	lastLaunch  LaunchRequest
	lastTag     string
	lastLines   int

	readyGate chan struct{}
}

func (d *fakeDriver) KVM(context.Context) error {
	d.mu.Lock()
	d.kvmCalls++
	d.mu.Unlock()
	return d.kvmErr
}

func (d *fakeDriver) CreateAVD(_ context.Context, taskID string) (taskAVD, error) {
	d.mu.Lock()
	d.createCalls++
	d.mu.Unlock()
	if d.avdErr != nil {
		return taskAVD{}, d.avdErr
	}
	return taskAVD{Name: avdPrefix + taskID, Home: "/tmp/" + taskID}, nil
}

func (d *fakeDriver) Start(context.Context, taskAVD) (process, error) {
	d.mu.Lock()
	d.startCalls++
	proc := d.proc
	d.mu.Unlock()
	if d.startErr != nil {
		return nil, d.startErr
	}
	return proc, nil
}

func (d *fakeDriver) Ready(ctx context.Context) error {
	d.mu.Lock()
	d.readyCalls++
	block := d.readyBlock
	gate := d.readyGate
	err := d.readyErr
	d.mu.Unlock()
	if block {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

func (d *fakeDriver) Shutdown(_ context.Context, p process) error {
	d.mu.Lock()
	d.shutdowns++
	d.mu.Unlock()
	if p != nil {
		_ = p.Kill()
	}
	return nil
}

// Dynamic operations record their calls so tests can assert the guard works.
func (d *fakeDriver) Install(_ context.Context, apkPath string) (OpResult, error) {
	d.mu.Lock()
	d.installs++
	d.installPath = apkPath
	d.mu.Unlock()
	if d.installErr != nil {
		return OpResult{}, d.installErr
	}
	return OpResult{OK: true, Output: "package installed"}, nil
}

func (d *fakeDriver) Launch(_ context.Context, req LaunchRequest) (OpResult, error) {
	d.mu.Lock()
	d.launches++
	d.lastLaunch = req
	d.mu.Unlock()
	if d.launchErr != nil {
		return OpResult{}, d.launchErr
	}
	return OpResult{OK: true, Output: "Starting: Intent"}, nil
}

func (d *fakeDriver) Logs(_ context.Context, tag string, lines int) (OpResult, error) {
	d.mu.Lock()
	d.logCalls++
	d.lastTag, d.lastLines = tag, lines
	d.mu.Unlock()
	return OpResult{OK: true, Output: "I/ActivityManager: start proc"}, nil
}

func (d *fakeDriver) Packages(context.Context) (OpResult, error) {
	d.mu.Lock()
	d.packageCalls++
	d.mu.Unlock()
	return OpResult{OK: true, Output: "package:com.target.app"}, nil
}

func (d *fakeDriver) RemoveAVD(taskID string) error {
	d.mu.Lock()
	d.removed = append(d.removed, taskID)
	d.mu.Unlock()
	return nil
}

func (d *fakeDriver) Reap(context.Context) {
	d.mu.Lock()
	d.reaps++
	d.mu.Unlock()
}

func (d *fakeDriver) counts() (kvm, create, start, ready, shutdown int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.kvmCalls, d.createCalls, d.startCalls, d.readyCalls, d.shutdowns
}

func newTestSupervisor(t *testing.T, drv driver) *supervisor {
	t.Helper()
	return &supervisor{root: t.TempDir(), drv: drv, states: map[string]snapshot{}}
}

func waitForState(t *testing.T, s *supervisor, id string, want state) snapshot {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got := s.current(id)
		if got.State == want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s never reached %q (last %+v)", id, want, s.current(id))
	return snapshot{}
}

// waitForStateEnd waits until the task reaches want AND the boot pipeline has
// finished. The supervisor publishes a terminal state before it shuts the
// emulator down and removes the AVD — it fails fast by design — so a test that
// asserts cleanup counters must wait for bootDone as well, not just the state.
func waitForStateEnd(t *testing.T, s *supervisor, id string, want state) snapshot {
	t.Helper()
	got := waitForState(t, s, id, want)
	s.mu.Lock()
	rt := s.active
	s.mu.Unlock()
	if rt != nil && rt.taskID == id {
		select {
		case <-rt.bootDone:
		case <-time.After(10 * time.Second):
			t.Fatal("boot pipeline did not finish")
		}
	}
	return got
}

func TestStartBecomesReadyOnlyAfterADBProof(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)

	rec := httptest.NewRecorder()
	s.start(rec, taskRequest("42"))
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d", rec.Code)
	}
	var accepted snapshot
	decode(t, rec, &accepted)
	if accepted.State != stateStarting {
		t.Fatalf("start returned %q, want starting", accepted.State)
	}

	waitForState(t, s, "42", stateReady)

	kvm, create, start, ready, _ := drv.counts()
	if kvm != 1 || create != 1 || start != 1 || ready != 1 {
		t.Fatalf("kvm=%d create=%d start=%d ready=%d", kvm, create, start, ready)
	}
}

func TestStartIsIdempotentWhileActive(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("7"))
	waitForState(t, s, "7", stateReady)

	s.start(httptest.NewRecorder(), taskRequest("7"))

	kvm, create, start, _, _ := drv.counts()
	if kvm != 1 || create != 1 || start != 1 {
		t.Fatalf("second start repeated work: kvm=%d create=%d start=%d", kvm, create, start)
	}
}

func TestKVMFailureNeverReportsReady(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess(), kvmErr: errors.New("no kvm")}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	got := waitForState(t, s, "42", stateFailed)

	if got.Reason != reasonKVM {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonKVM)
	}
	_, create, start, ready, _ := drv.counts()
	if create != 0 || start != 0 || ready != 0 {
		t.Fatalf("work continued after KVM failure: create=%d start=%d ready=%d", create, start, ready)
	}
}

func TestBootTimeoutFailsAndCleansUp(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess(), readyErr: errors.New("still booting")}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	got := waitForStateEnd(t, s, "42", stateFailed)
	if got.Reason != reasonBoot {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonBoot)
	}

	drv.mu.Lock()
	shutdowns, removed := drv.shutdowns, append([]string(nil), drv.removed...)
	drv.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("shutdowns = %d, want 1", shutdowns)
	}
	if len(removed) != 1 || removed[0] != "42" {
		t.Fatalf("removed = %v, want [42]", removed)
	}
}

func TestProcessExitingBeforeReadyIsReportedAsExit(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess(), readyErr: errors.New("adb never saw device")}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	// The emulator dies while the supervisor is still waiting for boot proof.
	drv.proc.exit(errors.New("qemu died"))

	got := waitForState(t, s, "42", stateFailed)
	if got.Reason != reasonExited {
		t.Fatalf("reason = %q, want %q", got.Reason, reasonExited)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)

	// Stopping a task that never started is a no-op that reports stopped.
	rec := httptest.NewRecorder()
	s.stop(rec, taskRequest("42"))
	var got snapshot
	decode(t, rec, &got)
	if got.State != stateStopped {
		t.Fatalf("stop of idle task = %q", got.State)
	}

	drv.mu.Lock()
	shutdowns := drv.shutdowns
	drv.mu.Unlock()
	if shutdowns != 0 {
		t.Fatalf("idle stop shut down %d processes", shutdowns)
	}
}

func TestStopAfterReadyCleansUp(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	rec := httptest.NewRecorder()
	s.stop(rec, taskRequest("42"))
	var accepted snapshot
	decode(t, rec, &accepted)
	if accepted.State != stateStopping {
		t.Fatalf("stop returned %q, want stopping", accepted.State)
	}

	waitForState(t, s, "42", stateStopped)

	drv.mu.Lock()
	shutdowns, removed := drv.shutdowns, append([]string(nil), drv.removed...)
	drv.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("shutdowns = %d", shutdowns)
	}
	if len(removed) == 0 || removed[len(removed)-1] != "42" {
		t.Fatalf("AVD not removed: %v", removed)
	}
}

func TestSecondTaskConflictsWithActiveRuntime(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess(), readyBlock: true, readyGate: make(chan struct{})}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("1"))
	time.Sleep(20 * time.Millisecond)

	rec := httptest.NewRecorder()
	s.start(rec, taskRequest("2"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var got snapshot
	decode(t, rec, &got)
	if got.Reason != reasonBusy {
		t.Fatalf("reason = %q", got.Reason)
	}

	// Let the first task's boot pipeline finish before the test's TempDir is
	// removed, or its background writes race the cleanup.
	close(drv.readyGate)
	waitForStateEnd(t, s, "1", stateReady)
}

func TestInvalidTaskIDRejected(t *testing.T) {
	s := newTestSupervisor(t, &fakeDriver{})
	for _, id := range []string{"0", "-1", "abc", "../1", "", "1.5"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/tasks/"+id+"/start", nil)
		r.SetPathValue("id", id)
		s.start(rec, r)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("id %q status = %d, want 400", id, rec.Code)
		}
	}
}

func TestReconcileDowngradesPersistedReady(t *testing.T) {
	drv := &fakeDriver{}
	s := newTestSupervisor(t, drv)

	dir := filepath.Join(s.root, "tasks", "42")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.save(snapshot{TaskID: "42", State: stateReady, Progress: 100})
	s.mu.Unlock()

	if err := s.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	var got snapshot
	s.mu.Lock()
	got = s.readState("42")
	s.mu.Unlock()

	if got.State != stateFailed {
		t.Fatalf("persisted ready survived restart as %q", got.State)
	}
	drv.mu.Lock()
	reaps := drv.reaps
	drv.mu.Unlock()
	if reaps != 1 {
		t.Fatalf("reap calls = %d, want 1", reaps)
	}
}

func TestHealthNeverClaimsReadiness(t *testing.T) {
	s := newTestSupervisor(t, &fakeDriver{})
	rec := httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"ready", "boot", "android"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("health body claims readiness: %s", rec.Body.String())
		}
	}
}

func TestSnapshotPersistsAndReloads(t *testing.T) {
	s := newTestSupervisor(t, &fakeDriver{})
	s.mu.Lock()
	s.save(snapshot{TaskID: "9", State: stateBooting, Progress: 25})
	s.mu.Unlock()

	// A fresh supervisor has no memory and must read the durable snapshot.
	fresh := &supervisor{root: s.root, drv: &fakeDriver{}, states: map[string]snapshot{}}
	fresh.mu.Lock()
	got := fresh.readState("9")
	fresh.mu.Unlock()

	if got.State != stateBooting || got.Progress != 25 {
		t.Fatalf("reloaded = %+v", got)
	}
}

func TestStopDuringBootEndsStopped(t *testing.T) {
	// The boot proof is still running when stop arrives; the resulting boot
	// failure must not overwrite the explicit stop.
	drv := &fakeDriver{proc: newFakeProcess(), readyBlock: true, readyGate: make(chan struct{})}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateBooting)

	rec := httptest.NewRecorder()
	s.stop(rec, taskRequest("42"))
	var accepted snapshot
	decode(t, rec, &accepted)
	if accepted.State != stateStopping {
		t.Fatalf("stop returned %q, want stopping", accepted.State)
	}

	got := waitForState(t, s, "42", stateStopped)
	if got.Reason != "" {
		t.Fatalf("stopped task kept reason %q", got.Reason)
	}

	drv.mu.Lock()
	shutdowns := drv.shutdowns
	drv.mu.Unlock()
	if shutdowns != 1 {
		t.Fatalf("shutdowns = %d, want 1", shutdowns)
	}
	close(drv.readyGate)
}

// Dynamic operations must be refused unless the emulator is ready for this
// exact task. These are the tests that keep a "probe without a device" bug from
// ever reaching production.
func TestDynamicOpsRefusedBeforeReady(t *testing.T) {
	// readyBlock keeps the emulator in `booting`, so every op must refuse.
	drv := &fakeDriver{proc: newFakeProcess(), readyBlock: true, readyGate: make(chan struct{})}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateBooting)

	rec := httptest.NewRecorder()
	s.launch(rec, launchRequest("42", `{"component":"a.b/.C"}`))
	if rec.Code != http.StatusConflict {
		t.Fatalf("launch status = %d, want 409", rec.Code)
	}
	var res OpResult
	decode(t, rec, &res)
	if res.OK {
		t.Fatal("launch claimed success before ready")
	}

	drv.mu.Lock()
	launches := drv.launches
	drv.mu.Unlock()
	if launches != 0 {
		t.Fatalf("driver was called %d times before ready", launches)
	}

	// Release the blocked boot and let the pipeline finish before the test's
	// TempDir is removed.
	close(drv.readyGate)
	waitForStateEnd(t, s, "42", stateReady)
}

func TestDynamicOpsRefusedForUnknownTask(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	// Task 99 has no runtime at all.
	rec := httptest.NewRecorder()
	s.logs(rec, getRequest("99", "/v1/tasks/99/logs"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("logs for unknown task status = %d, want 409", rec.Code)
	}
}

func TestDynamicOpsRefusedAfterFailure(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess(), readyErr: errors.New("boot failed")}
	s := newTestSupervisor(t, drv)

	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateFailed)

	rec := httptest.NewRecorder()
	s.packages(rec, getRequest("42", "/v1/tasks/42/packages"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("packages on failed task = %d, want 409", rec.Code)
	}
}

func TestLaunchAllowedWhenReadyAndValidated(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	rec := httptest.NewRecorder()
	s.launch(rec, launchRequest("42", `{"component":"com.target.app/.Admin","extras":{"url":"https://attacker.test"}}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var res OpResult
	decode(t, rec, &res)
	if !res.OK {
		t.Fatalf("launch failed: %+v", res)
	}

	drv.mu.Lock()
	got := drv.lastLaunch
	drv.mu.Unlock()
	if got.Component != "com.target.app/com.target.app.Admin" {
		t.Fatalf("component = %q", got.Component)
	}
	if got.Extras["url"] != "https://attacker.test" {
		t.Fatalf("extras = %v", got.Extras)
	}
}

func TestLaunchRejectsInjectionWithBadRequest(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	rec := httptest.NewRecorder()
	s.launch(rec, launchRequest("42", `{"component":"a.b/.C;rm -rf /"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	drv.mu.Lock()
	launches := drv.launches
	drv.mu.Unlock()
	if launches != 0 {
		t.Fatalf("unsafe request reached the driver %d times", launches)
	}
}

func TestInstallRejectsNonAPKBody(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tasks/42/install", strings.NewReader("not a zip at all"))
	req.SetPathValue("id", "42")
	s.install(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	drv.mu.Lock()
	installs := drv.installs
	drv.mu.Unlock()
	if installs != 0 {
		t.Fatalf("non-APK reached the driver %d times", installs)
	}
}

func TestInstallAcceptsZipMagicAndUsesTaskArtifactsPath(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	// A minimal zip header is enough for the pre-flight check; the fake driver
	// does not parse the package.
	body := append([]byte("PK\x03\x04"), make([]byte, 64)...)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tasks/42/install", strings.NewReader(string(body)))
	req.SetPathValue("id", "42")
	s.install(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	drv.mu.Lock()
	path := drv.installPath
	installs := drv.installs
	drv.mu.Unlock()
	if installs != 1 {
		t.Fatalf("installs = %d", installs)
	}
	if !strings.Contains(path, "42") || !strings.HasSuffix(path, "target.apk") {
		t.Fatalf("install path = %q, want inside the task dir", path)
	}
}

func TestLogsBoundsLines(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	rec := httptest.NewRecorder()
	s.logs(rec, getRequest("42", "/v1/tasks/42/logs?lines=999999"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	drv.mu.Lock()
	lines := drv.lastLines
	drv.mu.Unlock()
	if lines > maxLogLines {
		t.Fatalf("lines = %d, over the bound %d", lines, maxLogLines)
	}
}

// The operation lock must be released on every path. A handler that forgets
// endOp deadlocks the sidecar on the next operation, so this test drives a
// second request and requires it to complete rather than hang.
func TestDynamicOperationsReleaseTheLock(t *testing.T) {
	drv := &fakeDriver{proc: newFakeProcess()}
	s := newTestSupervisor(t, drv)
	s.start(httptest.NewRecorder(), taskRequest("42"))
	waitForState(t, s, "42", stateReady)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Two sequential operations of different kinds: the second can only
		// proceed if the first released the lock.
		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			s.logs(rec, getRequest("42", "/v1/tasks/42/logs"))
			if rec.Code != http.StatusOK {
				t.Errorf("logs #%d status = %d", i, rec.Code)
			}
			rec = httptest.NewRecorder()
			s.packages(rec, getRequest("42", "/v1/tasks/42/packages"))
			if rec.Code != http.StatusOK {
				t.Errorf("packages #%d status = %d", i, rec.Code)
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("dynamic operations deadlocked: the operation lock was not released")
	}
}

func TestClampReasonBoundsAndStripsControlChars(t *testing.T) {	if got := clampReason("line\nbreak\x00"); strings.ContainsAny(got, "\n\x00") {
		t.Fatalf("control characters survived: %q", got)
	}
	long := strings.Repeat("x", 400)
	if got := clampReason(long); len(got) > 160 {
		t.Fatalf("reason not bounded: %d", len(got))
	}
}
