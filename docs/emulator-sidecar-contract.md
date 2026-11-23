# Optional emulator sidecar contract

The `emulator` Compose profile is opt-in and private. It runs a **real
QEMU-backed Android Emulator** with a pinned Android Virtual Device (AVD), not
a mock, health stub, or probing adapter.

ARTEX calls only the fixed service URL `http://emulator:8090` and the fixed
endpoints:

- `GET  /v1/tasks/{numeric-task-id}` — current lifecycle snapshot
- `POST /v1/tasks/{numeric-task-id}/start`
- `POST /v1/tasks/{numeric-task-id}/stop`

The response is JSON
`{ "task_id": "...", "state": "starting|booting|ready|stopping|stopped|failed", "reason": "...", "progress": 0..100, "updated_at": "..." }`.

## Readiness is proven, never assumed

`ready` is returned only after all of the following succeed against the real
Android runtime:

1. `/dev/kvm` can be opened, **and** `emulator -accel-check` reports usable KVM.
2. The emulator was launched with `-accel on`, so it fails instead of silently
   falling back to software CPU emulation.
3. `adb -s emulator-5554 get-state` reports exactly `device`.
4. `getprop sys.boot_completed` is `1`.
5. `getprop dev.bootcomplete` is `1`.
6. A shell command (`adb shell true`) succeeds.

None of these may be substituted by HTTP 200, process existence, a listening
port, or a container health check. `/healthz` deliberately reports only that the
supervisor is alive and says nothing about Android.

## Dynamic testing surface

A booted emulator alone cannot test anything, so the sidecar exposes the typed
operations the `mobile-apk` skill's dynamic stage needs. Every one of them
requires the task's emulator to be `ready`, and none of them accepts a command
string:

| Endpoint | Operation |
|---|---|
| `POST /v1/tasks/{id}/install` | Install uploaded APK bytes (`adb install -r -t`) |
| `POST /v1/tasks/{id}/launch` | Start a component with a validated intent (`am start`/`startservice`/`broadcast`) |
| `GET  /v1/tasks/{id}/logs` | Read recent logcat, optional tag filter (bounded) |
| `GET  /v1/tasks/{id}/packages` | List installed third-party packages |

There is deliberately **no shell endpoint**. `launch` accepts a component,
kind, action, data URI, MIME type, and string extras as separate validated
fields; the sidecar builds a fixed `adb` argv from them. Anything outside the
Android identifier charset is rejected rather than escaped, so shell
metacharacters, control characters, and non-UTF-8 never reach `adb`.

These are surfaced to the agent as `install_target_apk`, `launch_component`,
`read_logcat`, and `list_emulator_packages`. When no emulator is ready they
report that explicitly instead of returning an empty success, so a model cannot
mistake "no device" for "nothing found".

## Runtime and host requirements

- **Architecture: `linux/amd64` only.** The pinned system image is `x86_64`.
  ARM hosts are not supported and will not silently emulate x86_64.
- **Native Linux with usable `/dev/kvm`.** Hardware virtualisation must be
  enabled on the host. Docker Desktop on Windows/macOS does not provide this;
  the profile fails closed there with a bounded reason.
- Roughly 8 GB free disk for SDK + system image + task AVD, and several GB of
  RAM available to the emulator.

The sidecar image also builds on a non-Linux host, but it can only *run* on
Linux. On other platforms the supervisor's driver returns a fixed failure and
never reports `ready`.

## Isolation and security boundary

- One task-scoped AVD per runtime, in a task-scoped `ANDROID_AVD_HOME`, so tasks
  cannot read each other's emulator state.
- Only one emulator runs at a time; a second task receives HTTP 409 rather than
  sharing a device. This is a deliberate first-slice limit.
- On stop, failure, or process exit the task AVD directory is deleted.
- On sidecar restart, leftover emulator processes are reaped by matching **this
  sidecar's own task AVD paths** in `/proc/*/cmdline`, and any persisted
  non-stopped state is downgraded to `failed`. A persisted `ready` is never
  trusted across a restart.
- The service has only `/dev/kvm`. No published ports, no Docker socket, no
  ARTEX keys, no workspace mount, no `privileged: true`, and no added
  capabilities. ADB (5555) and the emulator console (5554) stay inside the
  container network.
- The sidecar accepts only a validated numeric task id plus start/stop. It
  exposes no arbitrary ADB, shell, path, image, or command surface.

## Scope of this slice

This slice boots a real AVD, proves Android readiness, and exposes the dynamic
operations that make the emulator useful for mobile pentesting: installing the
task's package, launching a component with an attacker-controlled intent,
reading logcat as evidence, and confirming what is installed.

APK installation is bounded to the task's own emulator and its own directory;
the uploaded bytes are never trusted as a path. What is **not** included, and
remains a separate authorized-artifact boundary:

- arbitrary `adb shell` or command execution,
- Frida server injection into the running emulator,
- network interception from inside the emulator,
- installing packages from remote sources or app stores.

Static APK analysis is entirely independent of this sidecar: it works with the
emulator disabled, absent, or failed.

## Provenance of dynamic evidence

A finding must distinguish what was observed from what was inferred. The
dynamic surface is designed for that: `launch_component` returns `am`'s own
output, `read_logcat` returns device logs, and neither fabricates a result. An
intent accepted with no observable effect is not evidence of exploitability, and
the tool descriptions say so.

## Pinned artifacts

Pins come from Google's published SDK metadata
(`https://dl.google.com/android/repository/repository2-1.xml` and
`sys-img2-1.xml`), and each was verified by downloading the archive and
comparing the digest before it was trusted.

| Component | Revision | Archive | Digest |
|---|---|---|---|
| Command-line tools | build `15859902` | `commandlinetools-linux-15859902_latest.zip` | SHA-256 `4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583` |
| Emulator | `37.3.10` (stable) | `emulator-linux_x64-16970787.zip` | SHA-1 `5f7314368fc6c05c937f6991bb4106214dc389e7` |
| Platform-tools | `37.0.3` | `platform-tools_r37.0.3-linux.zip` | SHA-1 `e1579b288a7ae4e9bc28dedec6a154d78b3c04ed` |
| System image | `system-images;android-35;google_apis;x86_64` rev `9` | `x86_64-35_r09.zip` | SHA-1 `0103e6dab21290c4b9d16550a3ce99476f884eef` |

Two details matter for reproducibility:

- Google attests **SHA-256** for the command-line tools and **SHA-1** for the
  emulator, platform-tools, and system images, so each artifact is verified with
  the algorithm upstream actually publishes.
- The command-line tools are pinned by URL and unpacked directly. The emulator,
  platform-tools, and system image are installed through `sdkmanager` from the
  stable channel (`--channel=0`), because `avdmanager` and the emulator require
  the package metadata that `sdkmanager` registers. Unpacking those archives by
  hand produces an SDK that `avdmanager` cannot resolve. The build then asserts
  the installed `Pkg.Revision` of each package, the API level, ABI, and tag, and
  fails if any of them differ, so a channel advance cannot silently change the
  runtime.

Two build-time behaviours are known and are handled explicitly rather than
assumed, because both were observed on a real build of this image:

- `avdmanager create avd --device pixel_2` prints
  `Could not load devices from …/devices.xml` and **exits 0** when the
  device-definition catalogue is absent (as it is with cmdline-tools alone), so
  `--device` is silently ignored and the AVD falls back to a default hardware
  profile. The build therefore asserts the binding that actually matters,
  `image.sysdir.1` pointing at the pinned system image, and prints the generated
  `config.ini`. Screen geometry does not affect install, `am`, or logcat.
- `groupadd`/`useradd` are provided by the `passwd` package, but they install to
  `/usr/sbin`, which is deliberately **not** on this image's pinned `PATH`. The
  Dockerfile invokes them by absolute path; calling them by bare name fails with
  `groupadd: not found` even with the package present.

The emulator pin is the **stable** channel build. The `37.4.x` entries in
Google's repository are preview-channel packages under a different license and
are deliberately not used.

## Licensing

These are Google Android SDK components under the Android SDK License
Agreement. Licenses are accepted non-interactively during the image build and
the license text is retained in the image. The SDK and system image are not
generally redistributable: review the terms before publishing this image or the
underlying archives.

## Verification status

Verified in this repository:

- Sidecar state machine: KVM failure, boot failure, process exit, idempotent
  start/stop, cross-task conflict, restart reconciliation, and the invariant
  that `ready` requires the ADB proof path. `go test ./...` in `sidecar/`.
- KVM gate: `accelUsable` is unit-tested against the emulator's own success and
  failure strings. A bare "mentions KVM" check is a false positive, because the
  failure messages name KVM too (`KVM is installed but not accessible`,
  `KVM requires a CPU that supports vmx or svm`).
- Dynamic-operation surface: typed intent validation (21 malformed/injection
  cases), fixed `am` argv construction, "never a shell", extras bounds, and the
  operation lock (a missing release deadlocks, and is tested).
- Real Linux driver cross-compiles and vets cleanly (`GOOS=linux GOARCH=amd64`).
- The image's user/group step is proven against `debian:bookworm-slim` with the
  same pinned `PATH`: bare `groupadd` does not resolve, the absolute path does.
- Backend lifecycle, snapshot persistence, and sanitization tests pass; the
  emulator tools are tested to reach a device with the exact component/extras,
  and to say "no emulator" (never an empty success) when none is wired.

**Not yet verified, and required before claiming emulator support:** a cold boot
of this image on a native Linux `x86_64` host with usable `/dev/kvm`, recording
`emulator -accel-check` output, the ADB readiness result, and a clean stop. The
development host for this change had no `/dev/kvm`, so that positive path is
unproven here by design rather than assumed.
