---
name: mobile-apk
description: "Invoke this skill when the task targets an Android application (APK/AAB) rather than a website: static analysis of the manifest, signing certificate, exported components, deep links and embedded credentials, plus the dynamic follow-up that proves an exported component reachable. Covers OWASP MASVS and the Mobile Top 10."
---

# Android APK Pentest Flow

This skill is the mobile counterpart of web-vuln. It assumes an APK has been supplied for an authorized engagement, and it works in two stages: a deterministic static pass that runs on the file, then a dynamic pass that needs a device or emulator and only runs when the engagement allows it.

The standing finding quality gates and the adversarial gate in your system prompt apply throughout. A static observation is not a finding until you can say what an attacker gains; an exported component is a candidate, not a vulnerability, until a hostile app reaches it.

Attribution: structure follows the OWASP Mobile Application Security Testing Guide (MASTG) and the Mobile Top 10 (2024), both CC BY-SA 4.0.

## Stage 1: static analysis (always)

Call `analyze_apk` on the package before anything else. It returns the manifest structure, signing state, exported components, deep links, permissions and any embedded credentials, each with the manifest element or file that justifies it. Do not re-derive those facts by hand with unzip and grep: the tool is deterministic and the report cites it.

What the tool cannot tell you, and you must judge:

- **Whether an exported component is reachable in a meaningful way.** Exported is a precondition. Read the component's name: a share target or a launcher is expected, a `*Admin*`, `*Debug*`, `*WebView*` or `*Upload*` activity is where the value is.
- **Whether a hardcoded credential is live.** A key in the dex is only worth reporting once you know what it grants. A Firebase URL that reads data is a finding; an expired Stripe test key is not.
- **Whether a provider's paths are traversable.** The manifest shows `authorities` and `grantUriPermissions`; it never shows the path validation logic. That lives in the code.

## Stage 2: reading the code (when the finding needs it)

If the engagement scope allows decompilation and a candidate needs the source to confirm, `jadx` is the tool. It is present in the image. Decompile to the workspace, never into the task's evidence directory, and read only the class named by the finding:

```
jadx -d /workdir/<task>/apk-src --no-res <path-to.apk>
```

Then read the specific component. The pattern to look for on an exported activity is `getIntent()` → `getStringExtra`/`getData` → a sink: a `WebView.loadUrl`, a `File`, an `Intent`, a database write, or a privileged API call. If the value flows from the intent into the sink without a caller check, the component is exploitable and the finding is real.

For a provider, look at `openFile` and `query`: if the `Uri` path is joined onto a base directory without canonicalization, `../` escapes the provider's own directory.

Do not decompile the whole package "to understand it". It costs time and the interesting classes are already named by the static pass.

## Stage 3: dynamic proof (only with a ready emulator)

Everything above is what the app declares. Proving it needs the target installed on a device you control, plus a hostile intent. ARTEX provides this through its optional emulator profile, surfaced as tools — do not shell out to `adb` yourself:

1. `install_target_apk` with the workspace path of the APK. It uploads and installs the package; the bytes never leave the task's own emulator.
2. `list_emulator_packages` to confirm the package is present before you rely on it.
3. `launch_component` with the exported component from `analyze_apk` and the extras the component expects. `component` is `package/class`; `kind` selects activity, service, or broadcast. This is the hostile-app step: `am start -n <package>/<component> --es <key> <value>`.
4. `read_logcat` immediately afterwards, optionally with a `tag` filter. This is your evidence: an exception naming a file path, a WebView fetching your URL, a permission check that did not fire.

If `install_target_apk` reports that no emulator is ready, the optional profile is not running for this task. Say so and stop: dynamic proof is unavailable, and the static observations stay static. Do not install tooling mid-engagement or claim a component is unexploitable because no device was present.

A component that accepts the intent but produces no observable log line is not a finding. Report the static observation as informational at most, and state exactly what was sent and what came back.

For a provider (`overpermissive_provider`), the same tools cover the reachability half: `launch_component` a component that queries it, then `read_logcat`. A `../` traversal inside a `content://` URI still needs an authorized artifact and is outside this surface.

## Triage by class

The tool returns canonical classes. What each one is worth, and what to do next:

| Class | Meaning | Next step |
|---|---|---|
| `exported_component` | Reachable by any local app, no permission | Read the component; prove the sink (stage 2/3) |
| `overpermissive_provider` | Provider grants URIs without a guard | Test path traversal (stage 2/3) |
| `insecure_deep_link` | Custom scheme, no ownership check | Check whether parameters drive a privileged action |
| `unverified_app_link` | http(s) host without autoVerify | Another app can claim the host; check link handling |
| `hardcoded_secret` | Credential shape in the package | Determine what it grants before reporting severity |
| `cleartext_traffic` | Plaintext HTTP permitted | Check whether any endpoint carrying auth data uses it |
| `debuggable_app` | Debug build shipped | With adb, `run-as <package>` reads app-private data |
| `backup_enabled` | App data in device backups | `adb backup` extraction, if the engagement allows |
| `weak_signing_scheme` | v1 only | Relevant to update integrity, not to a live attack |
| `debug_signing_certificate` | Shared debug key | Anyone can build a package the device treats as the same signer |
| `overprivileged_app` | Dangerous permission declared | Judge in the UI flow, not from the manifest alone |
| `native_code_present` | .so shipped | Memory-safety review is a separate, deeper engagement |
| `no_code_obfuscation` | Readable class names | Lowers the cost of everything above; informational |

## Boundaries

- Only analyse packages you are authorized to test. An APK from a public store is not automatically in scope; the engagement letter decides.
- Do not distribute a modified or repackaged APK outside the engagement.
- A hardcoded credential belongs in the report redacted. If it is live, notify the client through the agreed channel rather than exercising it beyond what proves the issue.
- Dynamic testing on a physical device only with the owner's consent, and never on a device holding third-party data.

## Reporting

Report one finding per component or per credential, not one per package. Each needs:

- the canonical class from the table above,
- the manifest element or file from the tool's evidence field,
- what an attacker gains, stated concretely,
- whether it was proven dynamically or remains a static observation.

Say plainly which findings are proven and which are candidates. A static-only report that presents every exported activity as a vulnerability is worse than one that separates the two.
