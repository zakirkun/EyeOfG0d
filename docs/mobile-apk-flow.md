# Mobile (APK) Pentest Flow

ARTEX was built for web and network targets: the asset model is
domain → service → endpoint, and every finding is tied to an HTTP exchange. An
Android application is a different artefact, and this document describes how the
APK flow fits into the existing task system without changing its model.

## Why "app" assets, not a new asset type

`assets` already carries `type = 'app'` with a unique index on `bundle_id`
(`uq_av2_app_bundle`) and on `app_name` when no bundle id is set. An Android
package has a bundle-shaped identifier — the `package` attribute in its
manifest — so an APK anchors to the existing app asset instead of introducing a
parallel table.

That matters for the rest of the system, which already knows how to:

- attribute an asset to a company and a task (`task_ids`, `company_source`),
- bind a finding to it (`findings` references the asset id),
- carry it through the Continuous Proof diff (the fingerprint hashes the asset
  ids, so an APK finding groups across runs by package without extra work),
- render it in the UI asset lists and reports, which already branch on `app`.

A `type = 'apk'` would have required touching every one of those. Reusing `app`
keeps the flow additive.

## The three stages

### 1. Static analysis (implemented, deterministic)

`mobile.Analyse` opens the package and reads four things without decompiling
Java:

| Source | What it yields |
|---|---|
| `AndroidManifest.xml` (binary XML or plain) | identity, sdk levels, security flags, components, deep links, permissions |
| APK Signing Block + `META-INF/*` | signing schemes (v1/v2/v3), certificate subject, debug-cert detection |
| zip index | native libraries, dex files, asset volume |
| dex string tables + `.so`/`resources.arsc` | embedded credentials |

The binary XML parser (`mobile/axml.go`) is a narrow implementation of the
Android resource chunk format. It is bounded in depth and in every read, because
the package is attacker-supplied input, and it rejects structurally inconsistent
documents rather than guessing. Plain-text manifests are accepted too, for
repackaged or hand-built test packages.

`mobile.Evaluate` turns `PackageInfo` into findings. It is pure — same input,
same output — and every finding carries the manifest element or file that
justifies it, plus its OWASP MASVS control and MASTG test id.

### 2. Code reading (operator or agent, when a candidate needs it)

`jadx` decompiles to the workspace for the classes a finding names. This stage is
not automatic: decompiling a whole package is slow and unnecessary when the
static pass has already named the interesting components.

### 3. Dynamic proof (optional emulator profile)

The static stages above need no device and no extra infrastructure. Dynamic proof
does, and it is opt-in by design: the emulator ships as a separate Compose
profile (`--profile emulator`) running a **real** QEMU-backed Android Emulator in
its own linux/amd64 sidecar image. `docker-compose.yml` explains the real
requirements (native Linux, usable `/dev/kvm`, several GB RAM); Windows and
macOS Docker Desktop cannot satisfy them and fail closed.

Enabling it takes **two** steps, and both are required:

```sh
# 1. Build the sidecar image (pinned SDK, ~40 min the first time).
docker compose --profile emulator build emulator

# 2. Start it *and* switch the backend's capability on.
ARTEX_EMULATOR_ENABLED=1 docker compose --profile emulator up -d
```

Starting the profile alone is not enough: `ARTEX_EMULATOR_ENABLED` defaults to
`0`, which is what makes the backend report the capability as disabled and gives
every dynamic tool a clean "no emulator" result. The flag is a deliberate second
gate. A profile without the flag advertises a runtime the backend will not use;
the flag without the profile points the backend at a sidecar that is not running,
which surfaces as "sidecar is unreachable" rather than as a fake success.

The default backend image still carries the mobile *static* toolchain only. The
emulator is never installed mid-engagement, and a host without the profile gets a
clean "no emulator is ready" answer from every dynamic tool rather than an
attempt to improvise one.

The runtime contract is in [`emulator-sidecar-contract.md`](emulator-sidecar-contract.md):
readiness requires `emulator -accel-check` to report usable KVM, ADB to report
the device as `device`, **both** `sys.boot_completed` and `dev.bootcomplete` to
be `1`, and a live shell command to succeed. HTTP 200, a listening port, or a
running process is never treated as readiness.

When a device is ready, the procedure is: install the package, launch the
component with an intent you control, then read logcat as evidence.

## Agent surface

The mobile surface is six tools, split by what they need:

| Tool | Kind | Needs a device | Purpose |
|---|---|---|---|
| `analyze_apk` | read | no | Static manifest, signing, and credential facts |
| `build_frida_script` | read | no | Render an instrumentation script |
| `install_target_apk` | write | yes | Upload and install the task's package |
| `launch_component` | write | yes | Start an exported component with a typed intent |
| `read_logcat` | read | yes | Read recent device logs as evidence |
| `list_emulator_packages` | read | yes | Confirm what the device actually has |

`install_target_apk` and `launch_component` are write tools because they mutate
device state and must not run concurrently against one emulator; the observation
tools are read-only. None of them accept a command string: `launch_component`
takes typed fields (`component`, `kind`, `action`, `data`, `mime`, `extras`) and
the sidecar builds a fixed `adb`/`am` argv from values that passed the Android
identifier validators.

Deliberately **not** built: a `Bash`-reachable path into the sidecar. The sidecar
exposes no endpoint that accepts an arbitrary command, and the agent tools have no
`Run(command)` method. Adding one would turn a validated, typed surface back into
arbitrary remote execution inside the container that holds the device.

An absent emulator is reported as an absent emulator, never as a negative
finding: "no device" and "nothing found" must not look the same to a model.

## Vulnerability classes

The `MOBILE` category was added to `knowledge/data/vuln_ontology.json` with 15
children. Without it, every APK finding would fall through the unknown-class
fallback in `canonicalVulnClass`, and the Continuous Proof diff would still work
— unknown classes group with themselves — but the classes would be invisible to
the ontology queries that map a class to its CWE parent and escalation targets.

`db/vulnclass_table.go` is generated from that corpus by
`scripts/gen_vulnclass_table.py`, which mirrors `knowledge.buildClassIndex`
exactly. Regenerate it after editing the ontology; never hand-edit the table.

One consequence worth knowing: `rce` is claimed by two classes in the corpus
(`COMMAND_INJECTION` through a signal keyword, `CODE_EXECUTION` through an
ontology synonym), so the derivation drops it as ambiguous and it stays literal.
That is the corpus's own behaviour, not an artifact of the table.

## Known limits

- **Static only, in this image.** No device, so an exported component is
  reported as a reachable surface, never as a proven exploit.
- **Location granularity.** The fingerprint hashes class + asset ids + location.
  APK findings pass the component name or authority as location, so two exported
  activities on one package are two findings, but two findings of the same class
  in one component collapse. This is the same limitation `AddFinding` has for web
  findings, which pass an empty location.
- **Secret patterns are prefix-anchored.** A generic entropy heuristic would
  produce false positives that cost an operator more time than they save, so only
  provider-specific formats are matched. A high-entropy string with no known
  format is not reported.
- **No AAB support.** `.aab` bundles have a different layout; they must be
  converted to an APK (bundletool) before analysis.

## Testing

`mobile/mobile_test.go` builds real zip archives with plain-XML manifests and
exercises the whole path: identity, manifest flags, exported-component defaults,
deep links, the clean-package false-positive guard, secret redaction, SDK
comparison, and the non-zip and missing-manifest error paths.

`db/class_alias_test.go` asserts every mobile class is canonical, so a finding
class can never silently fall out of the vocabulary.