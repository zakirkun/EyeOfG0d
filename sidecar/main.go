// Command emulator-sidecar supervises one real Android Emulator AVD per task.
//
// It is Linux-only by construction: the image carries the pinned Android SDK,
// while /dev/kvm is supplied by the host. The HTTP surface is private and
// accepts no caller-supplied runtime configuration: a request may only name a
// numeric task id and choose start or stop.
//
// Readiness is never inferred from HTTP, process existence, or a listening
// port. It is only reported after adb proves the transport is `device`, both
// sys.boot_completed and dev.bootcomplete are 1, and a shell command succeeds.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const (
	listenAddr   = "0.0.0.0:8090"
	avdPrefix    = "artex-task-"
	emulatorPort = "5554"
	// adb addresses emulators as emulator-<console-port>.
	serial = "emulator-5554"

	kvmTimeout  = 25 * time.Second
	bootTimeout = 6 * time.Minute
	stopTimeout = 45 * time.Second

	// Per-operation budgets. These are the authoritative limits; the HTTP
	// server's transport timeouts below are derived from the largest of them,
	// because ReadTimeout/WriteTimeout apply to the whole request and would
	// otherwise sever a legitimate install mid-upload. An APK transfer plus
	// `adb install` is easily minutes, so a 60s transport cap would break the
	// one operation the dynamic surface exists for.
	installTimeout  = 4 * time.Minute
	launchTimeout   = 90 * time.Second
	logsTimeout     = 60 * time.Second
	packagesTimeout = 45 * time.Second
	// maxRequestBudget is the worst case across all handlers; the transport
	// timeouts are set from it so they can never be the binding constraint.
	maxRequestBudget = installTimeout

	reasonKVM     = "KVM acceleration is unavailable"
	reasonAVD     = "Android AVD could not be prepared"
	reasonStart   = "Android emulator process could not start"
	reasonBoot    = "Android emulator did not finish booting"
	reasonExited  = "emulator process exited unexpectedly"
	reasonBusy    = "another task emulator is active"
	reasonStorage = "emulator storage is unavailable"
	reasonCleanup = "emulator process cleanup timed out"
	reasonHost    = "emulator requires a Linux host with /dev/kvm"
)

var taskIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

type state string

const (
	stateStarting state = "starting"
	stateBooting  state = "booting"
	stateReady    state = "ready"
	stateStopping state = "stopping"
	stateStopped  state = "stopped"
	stateFailed   state = "failed"
)

// snapshot is the only shape the sidecar returns to the backend.
type snapshot struct {
	TaskID    string    `json:"task_id"`
	State     state     `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	Progress  int       `json:"progress,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// taskAVD identifies one provisioned task AVD.
type taskAVD struct {
	Name string
	Home string
}

// process is a running emulator. Done closes once the process has exited.
type process interface {
	Done() <-chan struct{}
	Err() error
	Terminate() error
	Kill() error
}

// driver isolates every Android/ADB interaction so the supervisor state
// machine can be tested without a KVM host or an emulator binary.
type driver interface {
	// KVM proves the device exists, is usable, and that the emulator agrees.
	KVM(ctx context.Context) error
	// CreateAVD provisions a fresh task-scoped AVD.
	CreateAVD(ctx context.Context, taskID string) (taskAVD, error)
	// Start launches the emulator for the given task AVD.
	Start(ctx context.Context, avd taskAVD) (process, error)
	// Ready blocks until Android has actually finished booting.
	Ready(ctx context.Context) error
	// Shutdown stops the emulator gracefully, then forcefully if needed.
	Shutdown(ctx context.Context, p process) error
	// Install installs a package file already held by the supervisor.
	Install(ctx context.Context, apkPath string) (OpResult, error)
	// Launch starts a validated component intent.
	Launch(ctx context.Context, req LaunchRequest) (OpResult, error)
	// Logs reads recent logcat output.
	Logs(ctx context.Context, tag string, lines int) (OpResult, error)
	// Packages lists third-party installed packages.
	Packages(ctx context.Context) (OpResult, error)
	// RemoveAVD deletes the task's AVD and writable state.
	RemoveAVD(taskID string) error
	// Reap terminates emulator processes left by an earlier sidecar run.
	Reap(ctx context.Context)
}

type runtime struct {
	taskID   string
	mu       sync.Mutex // guards avd and proc
	avd      taskAVD
	proc     process
	cancel   context.CancelFunc
	bootDone chan struct{}
}

type supervisor struct {
	mu     sync.Mutex
	root   string
	drv    driver
	active *runtime
	states map[string]snapshot
	// opMu serialises dynamic operations. The sidecar serves a single active
	// task, so one lock is sufficient, and it is necessary: install writes a
	// fixed path inside the task directory, so two concurrent uploads would
	// interleave and one could install the other's bytes.
	opMu sync.Mutex
}

func main() {
	s := newSupervisor()
	if err := s.reconcile(context.Background()); err != nil {
		log.Printf("emulator sidecar: startup reconciliation failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/tasks/{id}", s.status)
	mux.HandleFunc("POST /v1/tasks/{id}/start", s.start)
	mux.HandleFunc("POST /v1/tasks/{id}/stop", s.stop)
	// Dynamic surface. Every handler requires a ready emulator for this exact
	// task and validates its body before touching adb.
	mux.HandleFunc("POST /v1/tasks/{id}/install", s.install)
	mux.HandleFunc("POST /v1/tasks/{id}/launch", s.launch)
	mux.HandleFunc("GET /v1/tasks/{id}/logs", s.logs)
	mux.HandleFunc("GET /v1/tasks/{id}/packages", s.packages)

	srv := newHTTPServer(mux)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		s.shutdownAll()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("emulator sidecar listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("emulator sidecar stopped: %v", err)
	}
}

// newHTTPServer builds the HTTP server with its transport timeouts.
//
// The transport timeouts must exceed the largest handler budget, or a
// legitimate long operation is cut off by the server rather than by its own
// deadline: ReadTimeout covers the full request body (an APK upload runs to
// installTimeout) and WriteTimeout covers the response. Sizing them from
// maxRequestBudget keeps that true if a budget is tuned later. This function
// exists so a test can assert on the real server rather than on a copy.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Addr:              listenAddr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       maxRequestBudget + 30*time.Second,
		WriteTimeout:      maxRequestBudget + 30*time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func newSupervisor() *supervisor {
	root := os.Getenv("EMULATOR_STATE_DIR")
	if root == "" {
		root = "/var/lib/artex-emulator"
	}
	return &supervisor{root: root, drv: newAndroidDriver(root), states: map[string]snapshot{}}
}

func validTaskID(id string) bool { return taskIDPattern.MatchString(id) }

func (s *supervisor) taskDir(id string) string   { return filepath.Join(s.root, "tasks", id) }
func (s *supervisor) statePath(id string) string { return filepath.Join(s.taskDir(id), "state.json") }

// clampReason keeps persisted reasons short and free of control characters.
// Every reason this package emits is a fixed constant, so this is a guard, not
// a redaction boundary; the backend performs its own sanitization.
func clampReason(reason string) string {
	r := strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, strings.TrimSpace(reason))
	if len(r) > 160 {
		r = r[:160]
	}
	return r
}

// readState returns the in-memory snapshot, falling back to the last durable
// snapshot, then to a synthetic stopped entry. The caller must hold s.mu.
func (s *supervisor) readState(id string) snapshot {
	if v, ok := s.states[id]; ok {
		return v
	}
	if data, err := os.ReadFile(s.statePath(id)); err == nil {
		var v snapshot
		if json.Unmarshal(data, &v) == nil && v.TaskID == id {
			s.states[id] = v
			return v
		}
	}
	return snapshot{TaskID: id, State: stateStopped, UpdatedAt: time.Now().UTC()}
}

// save persists the snapshot. The caller must hold s.mu.
func (s *supervisor) save(v snapshot) snapshot {
	v.UpdatedAt = time.Now().UTC()
	v.Reason = clampReason(v.Reason)
	s.states[v.TaskID] = v
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	dir := s.taskDir(v.TaskID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return v
	}
	tmp := filepath.Join(dir, "state.json.tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return v
	}
	_ = os.Rename(tmp, s.statePath(v.TaskID))
	return v
}

func (s *supervisor) set(id string, st state, progress int, reason string) snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.readState(id)
	v.State, v.Progress, v.Reason = st, progress, reason
	return s.save(v)
}

func (s *supervisor) setProc(rt *runtime, p process) {
	rt.mu.Lock()
	rt.proc = p
	rt.mu.Unlock()
}

func (s *supervisor) getProc(rt *runtime) process {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.proc
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func requestTaskID(r *http.Request) (string, bool) {
	id := r.PathValue("id")
	return id, validTaskID(id)
}

func (s *supervisor) health(w http.ResponseWriter, _ *http.Request) {
	// Deliberately says nothing about Android readiness. A reachable sidecar
	// is not a booted emulator.
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *supervisor) status(w http.ResponseWriter, r *http.Request) {
	id, ok := requestTaskID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		return
	}
	writeJSON(w, http.StatusOK, s.current(id))
}

// current reports the persisted state, downgrading a stale `ready` when the
// emulator process is already gone.
func (s *supervisor) current(id string) snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.readState(id)
	rt := s.active
	if rt != nil && rt.taskID == id && v.State == stateReady {
		if p := s.getProc(rt); p != nil {
			select {
			case <-p.Done():
				v.State, v.Progress, v.Reason = stateFailed, 0, reasonExited
				v = s.save(v)
			default:
			}
		}
	}
	return v
}

func (s *supervisor) start(w http.ResponseWriter, r *http.Request) {
	id, ok := requestTaskID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		return
	}

	s.mu.Lock()
	current := s.readState(id)
	if current.State == stateStarting || current.State == stateBooting || current.State == stateReady {
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, current)
		return
	}
	if s.active != nil && s.active.taskID != id {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, snapshot{TaskID: id, State: stateFailed, Reason: reasonBusy, UpdatedAt: time.Now().UTC()})
		return
	}
	if err := os.MkdirAll(s.taskDir(id), 0o700); err != nil {
		current.State, current.Progress, current.Reason = stateFailed, 0, reasonStorage
		s.save(current)
		s.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, current)
		return
	}

	rt := &runtime{taskID: id, bootDone: make(chan struct{})}
	s.active = rt
	current.State, current.Progress, current.Reason = stateStarting, 5, ""
	saved := s.save(current)
	s.mu.Unlock()

	go s.boot(rt)
	writeJSON(w, http.StatusOK, saved)
}

// boot advances starting -> booting -> ready, and only the real boot proof in
// driver.Ready may produce ready.
func (s *supervisor) boot(rt *runtime) {
	defer close(rt.bootDone)

	ctx, cancel := context.WithTimeout(context.Background(), bootTimeout)
	rt.mu.Lock()
	rt.cancel = cancel
	rt.mu.Unlock()
	defer cancel()

	// KVM is the first gate: without working acceleration the emulator would
	// either refuse to start or crawl under software CPU emulation.
	if err := s.drv.KVM(ctx); err != nil {
		s.fail(rt, reasonKVM)
		return
	}

	avd, err := s.drv.CreateAVD(ctx, rt.taskID)
	if err != nil {
		s.fail(rt, reasonAVD)
		return
	}
	rt.mu.Lock()
	rt.avd = avd
	rt.mu.Unlock()

	if err := ctx.Err(); err != nil {
		s.fail(rt, reasonBoot)
		return
	}

	proc, err := s.drv.Start(ctx, avd)
	if err != nil {
		s.fail(rt, reasonStart)
		return
	}
	s.setProc(rt, proc)
	s.set(rt.taskID, stateBooting, 25, "")

	// Cancel the boot proof the moment the emulator exits, so a dead process
	// fails fast instead of waiting out the whole boot timeout.
	readyCtx, readyCancel := context.WithCancel(ctx)
	defer readyCancel()
	go func() {
		select {
		case <-proc.Done():
			readyCancel()
		case <-readyCtx.Done():
		}
	}()

	if err := s.drv.Ready(readyCtx); err != nil {
		select {
		case <-proc.Done():
			s.fail(rt, reasonExited)
		default:
			s.fail(rt, reasonBoot)
		}
		return
	}

	s.set(rt.taskID, stateReady, 100, "")
	go s.watchExit(rt)
}

// watchExit downgrades a booted emulator that dies without being asked to.
func (s *supervisor) watchExit(rt *runtime) {
	proc := s.getProc(rt)
	if proc == nil {
		return
	}
	<-proc.Done()

	s.mu.Lock()
	v := s.readState(rt.taskID)
	if v.State == stateReady {
		v.State, v.Progress, v.Reason = stateFailed, 0, reasonExited
		s.save(v)
	}
	if s.active == rt {
		s.active = nil
	}
	s.mu.Unlock()

	_ = s.drv.RemoveAVD(rt.taskID)
}

// fail tears down a task runtime and records a bounded reason. It never
// overwrites an explicit stop.
func (s *supervisor) fail(rt *runtime, reason string) {
	s.mu.Lock()
	v := s.readState(rt.taskID)
	if v.State == stateStopping || v.State == stateStopped {
		s.mu.Unlock()
		return
	}
	v.State, v.Progress, v.Reason = stateFailed, 0, reason
	s.save(v)
	s.mu.Unlock()

	if p := s.getProc(rt); p != nil {
		ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		_ = s.drv.Shutdown(ctx, p)
		cancel()
	}

	_ = s.drv.RemoveAVD(rt.taskID)

	s.mu.Lock()
	if s.active == rt {
		s.active = nil
	}
	s.mu.Unlock()
}

// readyRuntime returns this task's runtime only when it is genuinely ready: the
// process is alive and the persisted state is `ready`. A dynamic operation is
// never attempted against a starting, stopped, or failed emulator, because the
// only honest answer then is a refusal.
func (s *supervisor) readyRuntime(id string) (*runtime, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt := s.active
	if rt == nil || rt.taskID != id {
		return nil, false
	}
	v := s.readState(id)
	if v.State != stateReady {
		return nil, false
	}
	p := s.getProc(rt)
	if p == nil {
		return nil, false
	}
	select {
	case <-p.Done():
		// The process died but the exit watcher has not run yet.
		v.State, v.Progress, v.Reason = stateFailed, 0, reasonExited
		s.save(v)
		return nil, false
	default:
	}
	return rt, true
}

// opGuard is the shared precondition for every dynamic endpoint. It writes the
// refusal itself so the handlers stay uniform.
func (s *supervisor) opGuard(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := requestTaskID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		return "", false
	}
	if _, ready := s.readyRuntime(id); !ready {
		writeJSON(w, http.StatusConflict, OpResult{OK: false, Reason: "emulator is not ready for this task"})
		return "", false
	}
	// Serialise the operation itself, not just the guard: readiness can be true
	// for both of two simultaneous callers, and install writes a fixed path.
	s.opMu.Lock()
	return id, true
}

// endOp releases the operation lock taken by opGuard. Every handler that gets a
// true from opGuard must defer this exactly once.
func (s *supervisor) endOp() { s.opMu.Unlock() }

// install accepts a raw APK body. The body is size-bounded and written inside
// the task's own directory; the caller never supplies a path.
func (s *supervisor) install(w http.ResponseWriter, r *http.Request) {
	id, ok := s.opGuard(w, r)
	if !ok {
		return
	}
	defer s.endOp()

	body := http.MaxBytesReader(w, r.Body, maxInstallBytes)
	dir := filepath.Join(s.taskDir(id), "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, OpResult{OK: false, Reason: reasonStorage})
		return
	}
	apkPath := filepath.Join(dir, "target.apk")
	f, err := os.OpenFile(apkPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, OpResult{OK: false, Reason: reasonStorage})
		return
	}
	n, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(apkPath)
		writeJSON(w, http.StatusBadRequest, OpResult{OK: false, Reason: "package upload was not readable"})
		return
	}
	if n == 0 {
		_ = os.Remove(apkPath)
		writeJSON(w, http.StatusBadRequest, OpResult{OK: false, Reason: "package upload was empty"})
		return
	}

	// An APK is a zip; check the magic before handing it to adb so an obviously
	// wrong body is refused here rather than by the device.
	if !isZipFile(apkPath) {
		_ = os.Remove(apkPath)
		writeJSON(w, http.StatusBadRequest, OpResult{OK: false, Reason: "package is not an APK"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), installTimeout)
	defer cancel()
	result, err := s.drv.Install(ctx, apkPath)
	if err != nil {
		result = OpResult{OK: false, Reason: clampReason(err.Error())}
	}
	writeJSON(w, http.StatusOK, result)
}

// launch starts a validated component intent.
func (s *supervisor) launch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.opGuard(w, r); !ok {
		return
	}
	defer s.endOp()
	var req LaunchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, OpResult{OK: false, Reason: "invalid launch request"})
		return
	}
	req, err := validateLaunch(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, OpResult{OK: false, Reason: clampReason(err.Error())})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), launchTimeout)
	defer cancel()
	result, opErr := s.drv.Launch(ctx, req)
	if opErr != nil {
		result = OpResult{OK: false, Reason: clampReason(opErr.Error())}
	}
	writeJSON(w, http.StatusOK, result)
}

// logs returns recent logcat output.
func (s *supervisor) logs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.opGuard(w, r); !ok {
		return
	}
	defer s.endOp()
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	lines := 200
	if raw := r.URL.Query().Get("lines"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			lines = n
		}
	}
	// Bound at the boundary, not only in the driver: the contract is that no
	// operation can ask for unbounded work.
	if lines <= 0 || lines > maxLogLines {
		lines = 200
	}

	ctx, cancel := context.WithTimeout(r.Context(), logsTimeout)
	defer cancel()
	result, err := s.drv.Logs(ctx, tag, lines)
	if err != nil {
		result = OpResult{OK: false, Reason: clampReason(err.Error())}
	}
	writeJSON(w, http.StatusOK, result)
}

// packages lists installed third-party packages.
func (s *supervisor) packages(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.opGuard(w, r); !ok {
		return
	}
	defer s.endOp()
	ctx, cancel := context.WithTimeout(r.Context(), packagesTimeout)
	defer cancel()
	result, err := s.drv.Packages(ctx)
	if err != nil {
		result = OpResult{OK: false, Reason: clampReason(err.Error())}
	}
	writeJSON(w, http.StatusOK, result)
}

// isZipFile accepts a local file whose leading bytes are the zip magic that
// every APK carries.
func isZipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return magic[0] == 'P' && magic[1] == 'K' && (magic[2] == 3 || magic[2] == 5)
}

func (s *supervisor) stop(w http.ResponseWriter, r *http.Request) {
	id, ok := requestTaskID(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task id"})
		return
	}

	s.mu.Lock()
	current := s.readState(id)
	rt := s.active
	if rt == nil || rt.taskID != id {
		current.State, current.Progress, current.Reason = stateStopped, 0, ""
		saved := s.save(current)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, saved)
		return
	}
	current.State, current.Progress, current.Reason = stateStopping, 90, ""
	saved := s.save(current)
	rt.mu.Lock()
	if rt.cancel != nil {
		rt.cancel()
	}
	rt.mu.Unlock()
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, saved)
	go s.stopRuntime(rt)
}

func (s *supervisor) stopRuntime(rt *runtime) {
	// Wait for the boot pipeline to release the AVD before shutting down, so a
	// half-started emulator is not orphaned behind us.
	select {
	case <-rt.bootDone:
	case <-time.After(bootTimeout + time.Second):
	}

	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	if p := s.getProc(rt); p != nil {
		_ = s.drv.Shutdown(ctx, p)
	}
	_ = s.drv.RemoveAVD(rt.taskID)

	s.mu.Lock()
	v := s.readState(rt.taskID)
	if v.State != stateFailed {
		v.State, v.Progress, v.Reason = stateStopped, 0, ""
		s.save(v)
	}
	if s.active == rt {
		s.active = nil
	}
	s.mu.Unlock()
}

// shutdownAll is the container-shutdown path: stop whatever is running and do
// not leave the AVD behind.
func (s *supervisor) shutdownAll() {
	s.mu.Lock()
	rt := s.active
	s.mu.Unlock()
	if rt == nil {
		return
	}
	rt.mu.Lock()
	if rt.cancel != nil {
		rt.cancel()
	}
	rt.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	if p := s.getProc(rt); p != nil {
		_ = s.drv.Shutdown(ctx, p)
	}
	_ = s.drv.RemoveAVD(rt.taskID)
}

// reconcile runs once at startup. Any task that was mid-flight belongs to a
// dead generation: its process is reaped and its state downgraded, because a
// persisted `ready` can never be trusted across a restart.
func (s *supervisor) reconcile(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Join(s.root, "tasks"), 0o700); err != nil {
		return err
	}
	s.drv.Reap(ctx)

	entries, err := os.ReadDir(filepath.Join(s.root, "tasks"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validTaskID(entry.Name()) {
			continue
		}
		s.mu.Lock()
		v := s.readState(entry.Name())
		if v.State != stateStopped {
			v.State, v.Progress, v.Reason = stateFailed, 0, "sidecar restarted while the emulator was active"
			s.save(v)
		}
		s.mu.Unlock()
	}
	return nil
}
