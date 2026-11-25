package server

// The emulator integration is intentionally a private, fixed contract. The
// backend is the lifecycle authority; the sidecar never receives credentials,
// arbitrary commands, paths, targets, or host ports. The checked-in sidecar is
// a fail-closed adapter until an approved Android runtime is supplied.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zakirkun/EyeOfG0d/agent"
	"github.com/zakirkun/EyeOfG0d/db"
)

const emulatorSidecarURL = "http://emulator:8090"

type EmulatorState string

const (
	EmulatorDisabled    EmulatorState = "disabled"
	EmulatorUnavailable EmulatorState = "unavailable"
	EmulatorStarting    EmulatorState = "starting"
	EmulatorBooting     EmulatorState = "booting"
	EmulatorReady       EmulatorState = "ready"
	EmulatorStopping    EmulatorState = "stopping"
	EmulatorStopped     EmulatorState = "stopped"
	EmulatorFailed      EmulatorState = "failed"
)

type EmulatorStateSnapshot struct {
	TaskID     string        `json:"task_id"`
	State      EmulatorState `json:"state"`
	Reason     string        `json:"reason,omitempty"`
	Progress   int           `json:"progress,omitempty"`
	UpdatedAt  time.Time     `json:"updated_at"`
	Generation uint64        `json:"generation,omitempty"`
}

type sidecarClient interface {
	Start(context.Context, string) (EmulatorStateSnapshot, error)
	Stop(context.Context, string) (EmulatorStateSnapshot, error)
	Status(context.Context, string) (EmulatorStateSnapshot, error)
	// Dynamic operations. Each is a fixed contract endpoint; none accepts a
	// command string.
	Install(context.Context, string, []byte) (EmulatorOpResult, error)
	Launch(context.Context, string, EmulatorLaunch) (EmulatorOpResult, error)
	Logs(context.Context, string, string, int) (EmulatorOpResult, error)
	Packages(context.Context, string) (EmulatorOpResult, error)
}

// EmulatorOpResult and EmulatorLaunch are the shared dynamic-operation types.
// They are declared in the agent package, which owns the tool-facing contract,
// and aliased here so the server and the tools agree by identity rather than by
// structurally identical duplicates.
type EmulatorOpResult = agent.EmulatorOpResult

type EmulatorLaunch = agent.EmulatorLaunch

type HTTPEmulatorClient struct {
	client  *http.Client
	baseURL string
}

func (c HTTPEmulatorClient) call(ctx context.Context, taskID, action string) (EmulatorStateSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, lifecycleTimeout)
	defer cancel()
	var out EmulatorStateSnapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/tasks/"+taskID+"/"+action, nil)
	if err != nil {
		return out, errors.New("sidecar request could not be created")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return out, errors.New("sidecar is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusConflict { return out, errors.New("another task emulator is active") }
		var failure struct { State EmulatorState `json:"state"`; Reason string `json:"reason"` }
		_ = json.NewDecoder(resp.Body).Decode(&failure)
		if failure.State != "" { out.State, out.Reason = failure.State, sanitizeReason(failure.Reason); return out, nil }
		return out, errors.New("sidecar refused the lifecycle request")
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, errors.New("sidecar returned an invalid response")
	}
	if out.State != EmulatorStarting && out.State != EmulatorBooting && out.State != EmulatorReady && out.State != EmulatorStopping && out.State != EmulatorStopped && out.State != EmulatorUnavailable && out.State != EmulatorFailed {
		return out, errors.New("sidecar returned an invalid state")
	}
	return out, nil
}
func (c HTTPEmulatorClient) Start(ctx context.Context, id string) (EmulatorStateSnapshot, error) {
	return c.call(ctx, id, "start")
}
func (c HTTPEmulatorClient) Stop(ctx context.Context, id string) (EmulatorStateSnapshot, error) {
	return c.call(ctx, id, "stop")
}
func (c HTTPEmulatorClient) Status(ctx context.Context, id string) (EmulatorStateSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, lifecycleTimeout)
	defer cancel()
	var out EmulatorStateSnapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/tasks/"+id, nil)
	if err != nil { return out, errors.New("sidecar request could not be created") }
	resp, err := c.client.Do(req); if err != nil { return out, errors.New("sidecar is unreachable") }; defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return out, errors.New("sidecar refused the status request") }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return out, errors.New("sidecar returned an invalid response") }
	return out, nil
}

// decodeOp reads a bounded operation result. A non-2xx response is surfaced as
// a failure result rather than an error, because the sidecar's refusals are
// meaningful to the model.
// decodeOp reads the sidecar's bounded result. A refused operation is returned
// as a failure result rather than an error, because the sidecar's refusals are
// meaningful to the model.
//
// The timeout lives on the request context, not on the HTTP client: lifecycle
// calls are fast, but an install transfers up to 256 MiB and installs it, and a
// logcat read can legitimately take tens of seconds. A single client-wide
// timeout would make every dynamic operation fail as "unreachable".
func decodeOp(resp *http.Response, err error) (EmulatorOpResult, error) {
	if err != nil {
		return EmulatorOpResult{}, errors.New("sidecar is unreachable")
	}
	defer resp.Body.Close()
	var out EmulatorOpResult
	dec := json.NewDecoder(io.LimitReader(resp.Body, 128<<10))
	if decodeErr := dec.Decode(&out); decodeErr != nil {
		return EmulatorOpResult{}, errors.New("sidecar returned an invalid response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if out.Reason == "" {
			out.Reason = "emulator refused the operation"
		}
		out.OK = false
	}
	return out, nil
}

// Install uploads the package bytes to the sidecar. The backend never sends a
// path: the sidecar writes them inside the task's own directory.
func (c HTTPEmulatorClient) Install(ctx context.Context, id string, apk []byte) (EmulatorOpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, instanceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/tasks/"+id+"/install", bytes.NewReader(apk))
	if err != nil {
		return EmulatorOpResult{}, errors.New("sidecar request could not be created")
	}
	req.Header.Set("Content-Type", "application/vnd.android.package-archive")
	return decodeOp(c.client.Do(req))
}

func (c HTTPEmulatorClient) Launch(ctx context.Context, id string, launch EmulatorLaunch) (EmulatorOpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, instanceTimeout)
	defer cancel()
	body, err := json.Marshal(launch)
	if err != nil {
		return EmulatorOpResult{}, errors.New("launch request could not be encoded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/tasks/"+id+"/launch", bytes.NewReader(body))
	if err != nil {
		return EmulatorOpResult{}, errors.New("sidecar request could not be created")
	}
	req.Header.Set("Content-Type", "application/json")
	return decodeOp(c.client.Do(req))
}

func (c HTTPEmulatorClient) Logs(ctx context.Context, id, tag string, lines int) (EmulatorOpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, instanceTimeout)
	defer cancel()
	endpoint := c.baseURL + "/v1/tasks/" + id + "/logs?lines=" + strconv.Itoa(lines)
	if tag != "" {
		endpoint += "&tag=" + url.QueryEscape(tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return EmulatorOpResult{}, errors.New("sidecar request could not be created")
	}
	return decodeOp(c.client.Do(req))
}

func (c HTTPEmulatorClient) Packages(ctx context.Context, id string) (EmulatorOpResult, error) {
	ctx, cancel := context.WithTimeout(ctx, instanceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/tasks/"+id+"/packages", nil)
	if err != nil {
		return EmulatorOpResult{}, errors.New("sidecar request could not be created")
	}
	return decodeOp(c.client.Do(req))
}

type Emulator struct {
	mu      sync.Mutex
	root    string
	enabled bool
	client  sidecarClient
	states  map[string]EmulatorStateSnapshot
	emit    func(*Task, db.Activity)
	capable func() (EmulatorState, string)
}

// Timeouts. Lifecycle calls (start/stop/status) are cheap round trips; a
// dynamic operation may transfer and install a package, so it needs its own
// budget. The HTTP client therefore carries no blanket timeout for the dynamic
// path — each request sets one on its context.
const (
	lifecycleTimeout = 4 * time.Second
	instanceTimeout  = 5 * time.Minute
)

// newSidecarClient builds the client the backend uses. It carries no blanket
// HTTP timeout: every request sets its own deadline on the context, so a
// start/stop round trip and a 256 MiB install are governed by explicit budgets
// instead of one number that has to serve both.
func newSidecarClient(baseURL string) HTTPEmulatorClient {
	return HTTPEmulatorClient{client: &http.Client{}, baseURL: baseURL}
}

func newEmulator(ctx context.Context, root string, emit func(*Task, db.Activity)) *Emulator {
	e := &Emulator{root: filepath.Join(root, "emulator"), enabled: os.Getenv("EYEOFG0D_EMULATOR_ENABLED") == "1", client: newSidecarClient(emulatorSidecarURL), states: map[string]EmulatorStateSnapshot{}, emit: emit}
	e.capable = e.capability
	_ = os.MkdirAll(e.root, 0o700)
	go func() { <-ctx.Done(); e.stopAll() }()
	return e
}

func (e *Emulator) capability() (EmulatorState, string) {
	if !e.enabled {
		return EmulatorDisabled, "emulator is disabled"
	}
	// The backend container does not receive /dev/kvm: the sidecar does. So the
	// backend can only check what it genuinely knows here (platform and the
	// pinned image's architecture) and must leave the functional KVM proof to
	// the sidecar. Checking /dev/kvm in this process would falsely report
	// `unavailable` on every correctly configured Linux host.
	if runtime.GOOS != "linux" {
		return EmulatorUnavailable, "emulator requires native Linux"
	}
	if runtime.GOARCH != "amd64" {
		return EmulatorUnavailable, "emulator requires linux/amd64"
	}
	return EmulatorStarting, ""
}

func sanitizeReason(reason string) string {
	s := strings.TrimSpace(reason)
	if s == "" {
		return ""
	}
	if len(s) > 160 {
		s = s[:160]
	}
	for _, forbidden := range []string{"/app/", "/dev/", "token", "secret", "password", "adb", "docker"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			return "emulator operation failed"
		}
	}
	return s
}

func (e *Emulator) load(id string) EmulatorStateSnapshot {
	if s, ok := e.states[id]; ok {
		return s
	}
	data, err := os.ReadFile(filepath.Join(e.root, id+".json"))
	if err == nil {
		var s EmulatorStateSnapshot
		if json.Unmarshal(data, &s) == nil {
			if s.State == EmulatorStarting || s.State == EmulatorBooting || s.State == EmulatorReady || s.State == EmulatorStopping {
				s.State, s.Reason = EmulatorFailed, "backend restarted while emulator was active"
				s.UpdatedAt = time.Now().UTC()
				e.snapshot(s)
			}
			e.states[id] = s
			return s
		}
	}
	return EmulatorStateSnapshot{TaskID: id, State: EmulatorStopped, UpdatedAt: time.Now().UTC()}
}

func (e *Emulator) snapshot(s EmulatorStateSnapshot) {
	s.Reason = sanitizeReason(s.Reason)
	e.states[s.TaskID] = s
	b, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := filepath.Join(e.root, s.TaskID+".tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(e.root, s.TaskID+".json"))
	}
}

func (e *Emulator) status(id string) EmulatorStateSnapshot {
	e.mu.Lock()
	s := e.load(id)
	state, reason := e.capable()
	if state != EmulatorStarting { s.State, s.Reason, s.UpdatedAt = state, reason, time.Now().UTC(); e.snapshot(s); e.mu.Unlock(); return s }
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second); defer cancel()
	remote, err := e.client.Status(ctx, id)
	if err != nil { e.mu.Lock(); s = e.load(id); if s.State == EmulatorStarting || s.State == EmulatorBooting || s.State == EmulatorReady || s.State == EmulatorStopping { s.State, s.Reason, s.Progress = EmulatorFailed, "emulator sidecar is unavailable", 0; e.transitionState(s) }; e.mu.Unlock(); return s }
	remote.TaskID = id
	e.mu.Lock()
	if remote.State != s.State || remote.Progress != s.Progress || remote.Reason != s.Reason { s = e.transitionSnapshot(remote) } else { s = remote; e.snapshot(s) }
	e.mu.Unlock()
	return s
	}

func (e *Emulator) transitionState(s EmulatorStateSnapshot) { e.snapshot(s) }
func (e *Emulator) transitionSnapshot(s EmulatorStateSnapshot) EmulatorStateSnapshot {
	s.UpdatedAt = time.Now().UTC(); e.snapshot(s)
	if e.emit != nil { metadata, _ := json.Marshal(map[string]any{"emulator_state": s.State, "progress": s.Progress}); e.emit(&Task{ID:s.TaskID}, db.Activity{Worker:"system", Kind:"emulator", IsError:s.State == EmulatorFailed, Summary:"Android emulator " + string(s.State), Metadata:metadata}) }
	return s
}

func (e *Emulator) transition(t *Task, s EmulatorStateSnapshot) EmulatorStateSnapshot {
	s.TaskID = t.ID
	s.UpdatedAt = time.Now().UTC()
	e.snapshot(s)
	if e.emit != nil {
		metadata, _ := json.Marshal(map[string]any{"emulator_state": s.State, "progress": s.Progress})
		e.emit(t, db.Activity{Worker: "system", Kind: "emulator", IsError: s.State == EmulatorFailed || s.State == EmulatorUnavailable, Summary: "Android emulator " + string(s.State), Metadata: metadata})
	}
	return s
}

func (e *Emulator) start(ctx context.Context, t *Task) (EmulatorStateSnapshot, error) {
	e.mu.Lock()
	current := e.load(t.ID)
	if current.State == EmulatorReady || current.State == EmulatorStarting || current.State == EmulatorBooting {
		e.mu.Unlock()
		return current, nil
	}
	state, reason := e.capable()
	if state != EmulatorStarting {
		current.State, current.Reason = state, reason
		e.transition(t, current)
		e.mu.Unlock()
		return current, errors.New(reason)
	}
	current.State, current.Reason, current.Progress = EmulatorStarting, "", 10
	e.transition(t, current)
	e.mu.Unlock()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := e.client.Start(callCtx, t.ID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		current.State, current.Reason, current.Progress = EmulatorFailed, sanitizeReason(err.Error()), 0
		return e.transition(t, current), err
	}
	result.TaskID = t.ID
	return e.transition(t, result), nil
}

func (e *Emulator) stop(ctx context.Context, t *Task) (EmulatorStateSnapshot, error) {
	e.mu.Lock()
	current := e.load(t.ID)
	if current.State == EmulatorStopped || current.State == EmulatorDisabled || current.State == EmulatorUnavailable {
		e.mu.Unlock()
		return current, nil
	}
	current.State, current.Progress = EmulatorStopping, 90
	e.transition(t, current)
	e.mu.Unlock()
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := e.client.Stop(callCtx, t.ID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		current.State, current.Reason, current.Progress = EmulatorFailed, sanitizeReason(err.Error()), 0
		return e.transition(t, current), err
	}
	result.TaskID = t.ID
	return e.transition(t, result), nil
}

// Ready reports whether this task has a booted emulator. It is the gate the
// agent tools consult before offering a dynamic operation, and it is
// deliberately conservative: only a locally recorded `ready` counts.
func (e *Emulator) Ready(taskID string) bool {
	// Disabled is checked before anything else: a deployment without the
	// emulator profile must answer "no" without consulting a capability probe
	// that may not be wired.
	if !e.enabled || taskID == "" {
		return false
	}
	if state, _ := e.capable(); state != EmulatorStarting {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.load(taskID).State == EmulatorReady
}

// ensureReady is the single gate for every dynamic operation: the emulator must
// be enabled, capable on this host, and locally recorded as ready. It never
// infers readiness from a reachable sidecar.
func (e *Emulator) ensureReady(id string) error {
	if state, reason := e.capable(); state != EmulatorStarting {
		if reason == "" {
			reason = "emulator is unavailable"
		}
		return errors.New(reason)
	}
	e.mu.Lock()
	state := e.load(id).State
	e.mu.Unlock()
	if state != EmulatorReady {
		return errors.New("emulator is not ready for this task")
	}
	return nil
}

// Install uploads a package to this task's emulator.
func (e *Emulator) Install(ctx context.Context, id string, apk []byte) (EmulatorOpResult, error) {
	if err := e.ensureReady(id); err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	if len(apk) == 0 {
		return EmulatorOpResult{OK: false, Reason: "package is empty"}, errors.New("package is empty")
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	res, err := e.client.Install(callCtx, id, apk)
	if err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	res.Reason = sanitizeReason(res.Reason)
	return res, nil
}

// Launch starts a component with a validated intent.
func (e *Emulator) Launch(ctx context.Context, id string, launch EmulatorLaunch) (EmulatorOpResult, error) {
	if err := e.ensureReady(id); err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := e.client.Launch(callCtx, id, launch)
	if err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	// The output can contain app-controlled text; bound and sanitize reasons
	// only. Output is evidence and is returned as-is, bounded by the sidecar.
	res.Reason = sanitizeReason(res.Reason)
	return res, nil
}

// Logs returns recent logcat output for a task.
func (e *Emulator) Logs(ctx context.Context, id, tag string, lines int) (EmulatorOpResult, error) {
	if err := e.ensureReady(id); err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	if lines <= 0 || lines > 2000 {
		lines = 200
	}
	callCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res, err := e.client.Logs(callCtx, id, tag, lines)
	if err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	res.Reason = sanitizeReason(res.Reason)
	return res, nil
}

// Packages lists installed third-party packages.
func (e *Emulator) Packages(ctx context.Context, id string) (EmulatorOpResult, error) {
	if err := e.ensureReady(id); err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := e.client.Packages(callCtx, id)
	if err != nil {
		return EmulatorOpResult{OK: false, Reason: sanitizeReason(err.Error())}, err
	}
	res.Reason = sanitizeReason(res.Reason)
	return res, nil
}

func (e *Emulator) stopAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, s := range e.states {
		if s.State == EmulatorReady || s.State == EmulatorStarting || s.State == EmulatorBooting {
			s.State, s.Reason = EmulatorFailed, "backend interrupted emulator"
			s.UpdatedAt = time.Now().UTC()
			e.snapshot(s)
			e.states[id] = s
		}
	}
}

func emulatorTaskID(r *http.Request) string {
	id := strings.TrimSpace(r.PathValue("id"))
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	return id
}
func (s *Server) emulatorTask(w http.ResponseWriter, r *http.Request) (*Task, bool) {
	id := emulatorTaskID(r)
	if id == "" {
		writeErr(w, 400, "invalid task id")
		return nil, false
	}
	t, ok := s.m.Task(id)
	if !ok {
		writeErr(w, 404, "task not found")
		return nil, false
	}
	return t, true
}
func (s *Server) emulatorStatus(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if ok {
		writeJSON(w, 200, s.emulator.status(t.ID))
	}
}
func (s *Server) emulatorStart(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	state, err := s.emulator.start(r.Context(), t)
	if err != nil {
		writeJSON(w, 503, state)
		return
	}
	writeJSON(w, 200, state)
}
func (s *Server) emulatorStop(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	state, err := s.emulator.stop(r.Context(), t)
	if err != nil {
		writeJSON(w, 503, state)
		return
	}
	writeJSON(w, 200, state)
}

// emulatorInstall accepts a raw APK upload and installs it into the task's
// emulator. The body is size-bounded; the file is never written by the backend.
func (s *Server) emulatorInstall(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	const maxAPK = 256 << 20
	apk, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPK))
	if err != nil {
		writeErr(w, 400, "package upload was not readable")
		return
	}
	if len(apk) == 0 {
		writeErr(w, 400, "package upload was empty")
		return
	}
	res, err := s.emulator.Install(r.Context(), t.ID, apk)
	if err != nil {
		writeJSON(w, 409, res)
		return
	}
	writeJSON(w, 200, res)
}

// emulatorLaunch starts a component with a validated intent body.
func (s *Server) emulatorLaunch(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	var launch EmulatorLaunch
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&launch); err != nil {
		writeErr(w, 400, "invalid launch request")
		return
	}
	res, err := s.emulator.Launch(r.Context(), t.ID, launch)
	if err != nil {
		writeJSON(w, 409, res)
		return
	}
	writeJSON(w, 200, res)
}

// emulatorLogs returns recent logcat output.
func (s *Server) emulatorLogs(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	lines := 200
	if raw := r.URL.Query().Get("lines"); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			lines = n
		}
	}
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	res, err := s.emulator.Logs(r.Context(), t.ID, tag, lines)
	if err != nil {
		writeJSON(w, 409, res)
		return
	}
	writeJSON(w, 200, res)
}

// emulatorPackages lists installed third-party packages.
func (s *Server) emulatorPackages(w http.ResponseWriter, r *http.Request) {
	t, ok := s.emulatorTask(w, r)
	if !ok {
		return
	}
	res, err := s.emulator.Packages(r.Context(), t.ID)
	if err != nil {
		writeJSON(w, 409, res)
		return
	}
	writeJSON(w, 200, res)
}
