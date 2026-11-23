//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Android package and device profile are fixed at build time. Nothing here is
// caller-selectable, so a task cannot request a different image or device.
const (
	systemImagePackage = "system-images;android-35;google_apis;x86_64"
	avdDevice          = "pixel_2"
	sdkRoot            = "/opt/android-sdk"
)

// androidDriver is the real Android Emulator integration. It shells out only
// to fixed, image-provided binaries with fixed arguments; the only variable
// input is an already-validated numeric task id.
type androidDriver struct {
	root     string
	sdk      string
	emulator string
	adb      string
}

func newAndroidDriver(root string) driver {
	sdk := os.Getenv("ANDROID_SDK_ROOT")
	if sdk == "" {
		sdk = sdkRoot
	}
	return &androidDriver{
		root:     root,
		sdk:      sdk,
		emulator: filepath.Join(sdk, "emulator", "emulator"),
		adb:      filepath.Join(sdk, "platform-tools", "adb"),
	}
}

func (d *androidDriver) taskDir(taskID string) string {
	return filepath.Join(d.root, "tasks", taskID)
}

func (d *androidDriver) avdHome(taskID string) string {
	return filepath.Join(d.taskDir(taskID), "avd")
}

// env is the fixed tool environment. ANDROID_AVD_HOME is scoped per task so an
// AVD cannot see or reuse another task's state.
func (d *androidDriver) env(avdHome string) []string {
	androidHome := filepath.Join(d.root, "android-home")
	env := []string{
		"ANDROID_SDK_ROOT=" + d.sdk,
		"ANDROID_HOME=" + d.sdk,
		"ANDROID_USER_HOME=" + androidHome,
		"HOME=" + androidHome,
		"PATH=" + filepath.Join(d.sdk, "platform-tools") + string(os.PathListSeparator) +
			filepath.Join(d.sdk, "emulator") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"LANG=C.UTF-8",
	}
	if avdHome != "" {
		env = append(env, "ANDROID_AVD_HOME="+avdHome)
	}
	return env
}

// KVM proves acceleration works, not merely that a device node exists: the
// emulator binary itself must report usable KVM acceleration.
func (d *androidDriver) KVM(ctx context.Context) error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm: %w", err)
	}
	_ = f.Close()

	checkCtx, cancel := context.WithTimeout(ctx, kvmTimeout)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, d.emulator, "-accel-check")
	cmd.Env = d.env("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("emulator -accel-check: %w (%s)", err, tail(string(out)))
	}
	// The exit status is not sufficient evidence: the output must carry the
	// numeric status and the "usable" wording. See accelUsable.
	if !accelUsable(string(out)) {
		return fmt.Errorf("emulator reported no usable KVM acceleration (%s)", tail(string(out)))
	}
	return nil
}

// CreateAVD provisions a fresh AVD inside a task-scoped home. It always
// recreates, so a restarted task never inherits stale or foreign state.
func (d *androidDriver) CreateAVD(ctx context.Context, taskID string) (taskAVD, error) {
	if !validTaskID(taskID) {
		return taskAVD{}, errors.New("invalid task id")
	}
	home := d.avdHome(taskID)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return taskAVD{}, err
	}

	name := avdPrefix + taskID
	avdmanager := filepath.Join(d.sdk, "cmdline-tools", "latest", "bin", "avdmanager")

	createCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(createCtx, avdmanager, "create", "avd",
		"--force",
		"--name", name,
		"--package", systemImagePackage,
		"--device", avdDevice,
	)
	cmd.Env = d.env(home)
	// avdmanager asks whether to customise the hardware profile; the default
	// profile is what we want, so answer no.
	cmd.Stdin = strings.NewReader("no\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return taskAVD{}, fmt.Errorf("avdmanager create: %w (%s)", err, tail(string(out)))
	}

	ini := filepath.Join(home, name+".ini")
	if _, err := os.Stat(ini); err != nil {
		return taskAVD{}, fmt.Errorf("AVD definition missing after create: %w", err)
	}
	return taskAVD{Name: name, Home: home}, nil
}

// Start launches one headless, accelerated emulator for the task AVD.
func (d *androidDriver) Start(ctx context.Context, avd taskAVD) (process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if avd.Name == "" || avd.Home == "" {
		return nil, errors.New("AVD was not prepared for this task")
	}

	// -accel on makes the emulator fail rather than silently fall back to
	// unusably slow software CPU emulation. -gpu software avoids requiring a
	// host GPU, and -no-snapshot keeps every boot a real cold boot.
	args := []string{
		"-avd", avd.Name,
		"-port", emulatorPort,
		"-no-window",
		"-no-audio",
		"-no-boot-anim",
		"-no-snapshot",
		"-no-metrics",
		"-accel", "on",
		"-gpu", "software",
	}

	cmd := exec.Command(d.emulator, args...)
	cmd.Env = d.env(avd.Home)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = &boundedLog{limit: 16384}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	p := &execProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// Ready is the only path to `ready`. It requires ADB to report the device as
// `device`, Android to report completed boot via two independent properties,
// and a live shell command to succeed.
func (d *androidDriver) Ready(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.transportReady(ctx) && d.bootComplete(ctx) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (d *androidDriver) adbOut(ctx context.Context, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(callCtx, d.adb, args...)
	cmd.Env = d.env("")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (d *androidDriver) transportReady(ctx context.Context) bool {
	out, err := d.adbOut(ctx, "-s", serial, "get-state")
	return err == nil && out == "device"
}

func (d *androidDriver) bootComplete(ctx context.Context) bool {
	for _, prop := range []string{"sys.boot_completed", "dev.bootcomplete"} {
		out, err := d.adbOut(ctx, "-s", serial, "shell", "getprop", prop)
		if err != nil || out != "1" {
			return false
		}
	}
	_, err := d.adbOut(ctx, "-s", serial, "shell", "true")
	return err == nil
}

// Shutdown asks the emulator console to exit, then escalates through SIGTERM
// to SIGKILL. It returns only once the process is confirmed gone.
func (d *androidDriver) Shutdown(ctx context.Context, p process) error {
	if p == nil {
		return nil
	}
	select {
	case <-p.Done():
		return nil
	default:
	}

	killCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_ = exec.CommandContext(killCtx, d.adb, "-s", serial, "emu", "kill").Run()
	cancel()

	if waitOrDone(ctx, p, 15*time.Second) {
		return nil
	}

	_ = p.Terminate()
	if waitOrDone(ctx, p, 5*time.Second) {
		return nil
	}

	_ = p.Kill()
	if waitOrDone(ctx, p, 5*time.Second) {
		return nil
	}
	return errors.New(reasonCleanup)
}

func waitOrDone(ctx context.Context, p process, d time.Duration) bool {
	select {
	case <-p.Done():
		return true
	case <-time.After(d):
		return false
	case <-ctx.Done():
		select {
		case <-p.Done():
			return true
		default:
			return false
		}
	}
}

// Install copies a validated package into the emulator and installs it. The
// bytes come from a file the supervisor already holds, never from a path the
// caller supplies, and the install is a fixed adb invocation.
func (d *androidDriver) Install(ctx context.Context, apkPath string) (OpResult, error) {
	fi, err := os.Stat(apkPath)
	if err != nil {
		return OpResult{}, err
	}
	if fi.Size() <= 0 || fi.Size() > maxInstallBytes {
		return OpResult{}, errors.New("package size is outside the allowed range")
	}

	installCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// -r replaces an existing install so a retried task is idempotent; -t allows
	// a test-only package, which is common for engagement targets.
	cmd := exec.CommandContext(installCtx, d.adb, "-s", serial, "install", "-r", "-t", apkPath)
	cmd.Env = d.env("")
	out, err := cmd.CombinedOutput()
	text := tail(string(out))
	if err != nil {
		return OpResult{OK: false, Reason: clampReason("install failed: " + text)}, nil
	}
	if !strings.Contains(text, "Success") {
		return OpResult{OK: false, Reason: clampReason("install did not succeed: " + text)}, nil
	}
	return OpResult{OK: true, Output: "package installed"}, nil
}

// Launch starts a component with the validated intent fields.
func (d *androidDriver) Launch(ctx context.Context, req LaunchRequest) (OpResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(callCtx, d.adb, append([]string{"-s", serial}, launchArgs(req)...)...)
	cmd.Env = d.env("")
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return OpResult{OK: false, Reason: clampReason("am rejected the intent: " + tail(text))}, nil
	}
	// `am` reports failures on stdout with a non-zero status only sometimes, so
	// the text is checked too.
	for _, bad := range []string{"Error:", "Exception", "does not exist", "Permission Denial"} {
		if strings.Contains(text, bad) {
			return OpResult{OK: false, Reason: clampReason("am rejected the intent: " + tail(text))}, nil
		}
	}
	return OpResult{OK: true, Output: boundOutput(text)}, nil
}

// Logs reads recent logcat output, optionally filtered by a fixed tag. It is
// the observation half of dynamic testing: the evidence that a started
// component actually did something.
func (d *androidDriver) Logs(ctx context.Context, tag string, lines int) (OpResult, error) {
	if lines <= 0 || lines > maxLogLines {
		lines = 200
	}
	if tag != "" && !keyPattern.MatchString(tag) {
		return OpResult{}, errors.New("invalid log tag")
	}

	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	args := []string{"-s", serial, "logcat", "-d", "-v", "brief", "-t", strconv.Itoa(lines)}
	if tag != "" {
		// A fixed filter expression, not a caller-supplied one.
		args = append(args, tag+":V", "*:S")
	}
	cmd := exec.CommandContext(callCtx, d.adb, args...)
	cmd.Env = d.env("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return OpResult{OK: false, Reason: clampReason("logcat failed: " + tail(string(out)))}, nil
	}
	return OpResult{OK: true, Output: boundOutput(string(out))}, nil
}

// Packages lists installed packages so a task can confirm what is present.
func (d *androidDriver) Packages(ctx context.Context) (OpResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(callCtx, d.adb, "-s", serial, "shell", "pm", "list", "packages", "-3")
	cmd.Env = d.env("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return OpResult{OK: false, Reason: clampReason("package list failed: " + tail(string(out)))}, nil
	}
	return OpResult{OK: true, Output: boundOutput(string(out))}, nil
}

// boundOutput caps returned text so a single operation cannot exhaust the
// backend's response budget.
func boundOutput(s string) string {
	s = strings.TrimSpace(s)
	const limit = 64 << 10
	if len(s) > limit {
		return s[:limit] + "\n[output truncated]"
	}
	return s
}

// RemoveAVD deletes only a task directory beneath this sidecar's own state
// root, guarded by the numeric task-id shape.
func (d *androidDriver) RemoveAVD(taskID string) error {
	if !validTaskID(taskID) {
		return errors.New("invalid task id")
	}
	dir := d.taskDir(taskID)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	return os.RemoveAll(dir)
}

// Reap terminates emulator processes left behind by a previous sidecar
// generation. It matches only processes whose command line references this
// sidecar's own task AVD directory, so unrelated processes are never touched.
func (d *androidDriver) Reap(ctx context.Context) {
	entries, err := os.ReadDir(filepath.Join(d.root, "tasks"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validTaskID(entry.Name()) {
			continue
		}
		home := d.avdHome(entry.Name())
		// Both the launcher and the QEMU child carry the task AVD path in
		// their arguments, so one marker covers the whole process tree.
		for _, pid := range processesMentioning(home) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// processesMentioning finds PIDs whose command line contains marker.
func processesMentioning(marker string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, entry := range entries {
		pid, err := parseInt(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		if strings.Contains(string(raw), marker) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func parseInt(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not numeric")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// execProcess adapts *exec.Cmd to the process interface. Signals target the
// whole process group so QEMU children do not outlive the supervisor.
type execProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (p *execProcess) Done() <-chan struct{} { return p.done }
func (p *execProcess) Err() error            { return p.err }

func (p *execProcess) Terminate() error {
	if p.cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
}

func (p *execProcess) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
}

// boundedLog retains only the tail of emulator output. It is never exposed
// over HTTP; it exists so a failed boot can be diagnosed from container logs.
type boundedLog struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.limit {
		b.buf = b.buf[len(b.buf)-b.limit:]
	}
	return len(p), nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[len(s)-200:]
	}
	return s
}
