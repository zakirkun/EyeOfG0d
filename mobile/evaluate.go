package mobile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity mirrors the vocabulary the rest of EyeOfG0d uses so an APK finding
// sorts and filters alongside a web finding.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is one potential issue derived from a PackageInfo, already mapped to
// the OWASP MASVS control and MASTG test that justify it.
//
// Class is the canonical vulnerability token. It is deliberately a stable,
// normalised string: the Continuous Proof fingerprint groups findings across
// runs by (class, assets, location), so a class that changed spelling between
// runs would look like a regression. Android classes are not yet in the
// vulnerability corpus, so they pass through the unknown-class fallback and
// group with themselves - which is exactly the behaviour wanted.
type Finding struct {
	Class    string
	Title    string
	Severity string
	// MASVS is the OWASP MASVS control, e.g. "MASVS-STORAGE-2".
	MASVS string
	// MASTG is the OWASP MASTG test id that describes how to verify it.
	MASTG string
	// Detail explains what was observed, in the operator's terms.
	Detail string
	// Evidence is the exact manifest/library artefact behind the claim, so a
	// reviewer can confirm it without re-running the analysis.
	Evidence string
	// Location narrows where in the package the issue lives (component name,
	// library path). Empty when the issue is package-wide.
	Location string
	// Component is the Android component name when scoped to one.
	Component string
}

// Evaluate derives findings from an analysed package. It is pure: same input,
// same output, no clock, no network, no ordering instability.
func Evaluate(info *PackageInfo) []Finding {
	if info == nil {
		return nil
	}
	var out []Finding
	add := func(f Finding) { out = append(out, f) }

	// ---- manifest flags -------------------------------------------------
	if info.DebugFlagPresent && info.Debuggable {
		add(Finding{
			Class:    "debuggable_app",
			Title:    "Application is debuggable",
			Severity: SeverityHigh,
			MASVS:    "MASVS-RESILIENCE-2",
			MASTG:    "MASTG-TEST-0034",
			Detail:   "android:debuggable=\"true\" ships in a release package. Any app with adb access on the device can attach a debugger, read process memory and call non-public methods.",
			Evidence: `AndroidManifest.xml: <application android:debuggable="true">`,
		})
	}

	if info.AllowBackupPresent && info.AllowBackup {
		add(Finding{
			Class:    "backup_enabled",
			Title:    "Application data is included in device backups",
			Severity: SeverityMedium,
			MASVS:    "MASVS-STORAGE-2",
			MASTG:    "MASTG-TEST-0009",
			Detail:   "android:allowBackup is true, so app-private files can be extracted with adb backup or a full-device backup on a compromised or rooted device. Tokens and session stores are the usual exposure.",
			Evidence: `AndroidManifest.xml: android:allowBackup="true"`,
		})
	}

	if info.CleartextPresent && info.UsesCleartext {
		add(Finding{
			Class:    "cleartext_traffic",
			Title:    "Cleartext HTTP traffic explicitly permitted",
			Severity: SeverityHigh,
			MASVS:    "MASVS-NETWORK-1",
			MASTG:    "MASTG-TEST-0235",
			Detail:   "android:usesCleartextTraffic=\"true\" lets the app send plaintext HTTP. Anything on the path - a hostile network, a proxy, an upstream CDN - can read and modify it.",
			Evidence: `AndroidManifest.xml: android:usesCleartextTraffic="true"`,
		})
	}

	// A target SDK below 28 means cleartext is permitted by platform default,
	// even without the explicit flag.
	if info.TargetSDK != "" && sdkLessThan(info.TargetSDK, 28) && !info.CleartextPresent {
		add(Finding{
			Class:    "cleartext_traffic",
			Title:    "Cleartext traffic permitted by a low targetSdkVersion",
			Severity: SeverityMedium,
			MASVS:    "MASVS-NETWORK-1",
			MASTG:    "MASTG-TEST-0235",
			Detail:   fmt.Sprintf("targetSdkVersion is %s, below 28, so the platform permits cleartext HTTP regardless of android:usesCleartextTraffic. Raising it forces an explicit opt-in.", info.TargetSDK),
			Evidence: fmt.Sprintf("AndroidManifest.xml: <uses-sdk android:targetSdkVersion=\"%s\">", info.TargetSDK),
		})
	}

	// ---- signing --------------------------------------------------------
	if !info.Signed {
		add(Finding{
			Class:    "unsigned_apk",
			Title:    "Package is not signed",
			Severity: SeverityHigh,
			MASVS:    "MASVS-CODE-3",
			MASTG:    "MASTG-TEST-0018",
			Detail:   "No v1, v2 or v3 signature was found. The package cannot be installed by normal means and its provenance cannot be attributed, so any distribution of it is unverified.",
			Evidence: "no META-INF/*.RSA|DSA|EC and no APK Signing Block",
		})
	} else {
		// Scheme strength: Android 11+ verifies v2 and above; a v1-only
		// signature is vulnerable to the Janus-style class of attacks and is
		// rejected outright from Android 14 for new installs.
		if !info.SigningV2 && !info.SigningV3 {
			add(Finding{
				Class:    "weak_signing_scheme",
				Title:    "Only the v1 (JAR) signature scheme is present",
				Severity: SeverityMedium,
				MASVS:    "MASVS-CODE-3",
				MASTG:    "MASTG-TEST-0018",
				Detail:   "The package carries no APK Signing Block, so only v1 signing protects it. v1 alone does not cover the whole archive and is not accepted for new installs on recent Android releases.",
				Evidence: "META-INF signature present; no v2/v3 APK Signing Block",
			})
		}
		for _, sig := range info.Signatures {
			if sig.IsDebugCert {
				add(Finding{
					Class:    "debug_signing_certificate",
					Title:    "Package is signed with the Android debug certificate",
					Severity: SeverityHigh,
					MASVS:    "MASVS-RESILIENCE-1",
					MASTG:    "MASTG-TEST-0018",
					Detail:   "The signing certificate is the shared debug keystore. Anyone holding the well-known debug key can produce a package the platform treats as the same signer, so update integrity is void.",
					Evidence: fmt.Sprintf("signer subject: %s", sig.Subject),
					Location: sig.SHA256,
				})
			}
			if sig.SelfSigned && !sig.IsDebugCert {
				add(Finding{
					Class:    "self_signed_certificate",
					Title:    "Package is signed with a self-signed certificate",
					Severity: SeverityInfo,
					MASVS:    "MASVS-CODE-3",
					MASTG:    "MASTG-TEST-0018",
					Detail:   "Self-signed signing is normal for Android and is not a weakness in itself; recorded so the signer identity is auditable across releases. It becomes a issue only if the key is shared or reused across unrelated apps.",
					Evidence: fmt.Sprintf("signer subject: %s", sig.Subject),
					Location: sig.SHA256,
				})
			}
		}
	}

	// ---- exported components -------------------------------------------
	// An exported component without a permission is reachable by any other app
	// on the device. That is the precondition for the whole MASVS-PLATFORM
	// family, so it is reported per component rather than as one package-wide
	// line: the component name is what the operator has to go and test.
	byKind := map[string][]Component{
		"activity": info.Activities,
		"service":  info.Services,
		"receiver": info.Receivers,
		"provider": info.Providers,
	}
	kindOrder := []string{"activity", "service", "receiver", "provider"}
	for _, kind := range kindOrder {
		components := append([]Component(nil), byKind[kind]...)
		sort.Slice(components, func(i, j int) bool { return components[i].Name < components[j].Name })
		for _, c := range components {
			if !c.Exported || c.Permission != "" {
				continue
			}
			f := Finding{
				Class:     "exported_component",
				Severity:  severityForExportedComponent(kind, c),
				MASVS:     "MASVS-PLATFORM-1",
				MASTG:     mastgForExportedComponent(kind),
				Component: c.Name,
				Location:  c.Name,
			}
			switch kind {
			case "activity":
				f.Title = "Exported activity without a permission guard"
				f.Detail = "Any installed app can start this activity. If it accepts extras or a data URI and acts on them without validating the caller, that is a local privilege boundary crossing."
			case "service":
				f.Title = "Exported service without a permission guard"
				f.Detail = "Any installed app can bind to or start this service. Exported services that perform privileged work on behalf of the caller are the classic confused-deputy problem."
			case "receiver":
				f.Title = "Exported broadcast receiver without a permission guard"
				f.Detail = "Any installed app can send this receiver an Intent. Receivers that act on broadcast extras without authenticating the sender let a local app drive app behaviour."
			case "provider":
				f.Title = "Exported content provider without a permission guard"
				f.Detail = "Any installed app can query or modify this provider. If its paths are not validated, it exposes the files or database rows it serves, including traversal outside its own directory."
			}
			if kind == "provider" && c.GrantURIPermissions {
				f.Severity = SeverityHigh
				f.Detail += " It also sets grantUriPermissions, so a granted URI can be handed to a third party."
			}
			if c.ExportedPresent {
				f.Evidence = fmt.Sprintf(`AndroidManifest.xml: <%s android:name="%s" android:exported="true">`, kind, c.Name)
			} else {
				// Exported by platform default because of an intent filter.
				f.Evidence = fmt.Sprintf(`AndroidManifest.xml: <%s android:name="%s"> with %d intent-filter(s) and no android:exported (exported by default)`, kind, c.Name, c.IntentFilters)
			}
			add(f)
		}
	}

	// ---- providers with grantUriPermissions but no read/write permission --
	for _, p := range info.Providers {
		if !p.GrantURIPermissions || p.Permission != "" || !p.Exported {
			continue
		}
		add(Finding{
			Class:     "overpermissive_provider",
			Title:     "Content provider grants URI permissions without a permission guard",
			Severity:  SeverityHigh,
			MASVS:     "MASVS-PLATFORM-1",
			MASTG:     "MASTG-TEST-0357",
			Detail:    "grantUriPermissions is set and neither readPermission nor writePermission nor permission is declared, so a granted URI can be passed to another app that then reads it.",
			Evidence:  fmt.Sprintf(`AndroidManifest.xml: <provider android:name="%s" android:authorities="%s" android:grantUriPermissions="true">`, p.Name, p.Authorities),
			Component: p.Name,
			Location:  p.Authorities,
		})
	}

	// ---- deep links -----------------------------------------------------
	seenSchemes := map[string]bool{}
	for _, link := range info.DeepLinks {
		scheme := strings.ToLower(link.Scheme)
		// A custom scheme cannot be claimed exclusively: any app can register
		// the same one, so a link delivered through it has no trustworthy
		// origin. That is the finding, and it is per scheme.
		if scheme != "http" && scheme != "https" {
			if seenSchemes[scheme] {
				continue
			}
			seenSchemes[scheme] = true
			add(Finding{
				Class:     "insecure_deep_link",
				Title:     "Custom URL scheme used for deep links",
				Severity:  SeverityMedium,
				MASVS:     "MASVS-PLATFORM-2",
				MASTG:     "MASTG-TEST-0028",
				Detail:    "A custom scheme has no ownership check: any app on the device can register the same scheme and receive the link instead. Parameters carried this way cannot be treated as coming from a trusted source.",
				Evidence:  fmt.Sprintf("%s://%s%s", link.Scheme, link.Host, firstNonEmpty(link.Path, link.PathPref)),
				Component: link.Component,
				Location:  link.Scheme + "://",
			})
			continue
		}
		// http(s) without autoVerify is an unverified web link: the app claims
		// the host but the platform never checked the domain association, so
		// another app can intercept it.
		if !link.AutoVerify {
			key := "unverified|" + strings.ToLower(link.Host) + "|" + strings.ToLower(link.Scheme)
			if seenSchemes[key] {
				continue
			}
			seenSchemes[key] = true
			add(Finding{
				Class:     "unverified_app_link",
				Title:     "Web link is not verified with autoVerify",
				Severity:  SeverityMedium,
				MASVS:     "MASVS-PLATFORM-2",
				MASTG:     "MASTG-TEST-0393",
				Detail:    "The app handles an http(s) host but the intent filter omits android:autoVerify, so the platform never confirmed the domain association through /.well-known/assetlinks.json. Another app can register the same host and intercept the link.",
				Evidence:  fmt.Sprintf(`<data android:scheme="%s" android:host="%s"> without android:autoVerify`, link.Scheme, link.Host),
				Component: link.Component,
				Location:  link.Scheme + "://" + link.Host,
			})
		}
	}

	// ---- native code ----------------------------------------------------
	if len(info.NativeLibs) > 0 {
		add(Finding{
			Class:    "native_code_present",
			Title:    "Package ships native libraries",
			Severity: SeverityInfo,
			MASVS:    "MASVS-CODE-4",
			MASTG:    "MASTG-TEST-0036",
			Detail:   "Native code is outside the Java sandbox's safety guarantees and cannot be inspected by decompiling dex. Buffer overflows, format strings and unsafe JNI boundaries have to be reviewed in the .so files directly, not from the Java side.",
			Evidence: strings.Join(limitSlice(info.NativeLibs, 12), ", "),
			Location: "lib/",
		})
	}

	// ---- permissions ----------------------------------------------------
	for _, p := range info.Permissions {
		if isDangerousPermission(p.Name) {
			add(Finding{
				Class:    "overprivileged_app",
				Title:    fmt.Sprintf("Dangerous permission requested: %s", shortPermission(p.Name)),
				Severity: SeverityLow,
				MASVS:    "MASVS-PRIVACY-1",
				MASTG:    "MASTG-TEST-0024",
				Detail:   "A runtime-dangerous permission is declared. Each one is a capability the app can exercise over user data; verify in the UI flow that the capability is actually needed and requested at the point of use rather than at launch.",
				Evidence: fmt.Sprintf("<uses-permission android:name=%q>", p.Name),
				Location: p.Name,
			})
		}
	}

	// ---- cheap obfuscation signal --------------------------------------
	// A single dex with a very small class surface usually means the build was
	// not minified. This is informational: absence of obfuscation is not a
	// vulnerability, but it lowers the cost of the other findings.
	if len(info.DexFiles) == 1 && !info.HasObfuscationSignal {
		add(Finding{
			Class:    "no_code_obfuscation",
			Title:    "Code does not appear to be obfuscated",
			Severity: SeverityInfo,
			MASVS:    "MASVS-RESILIENCE-3",
			MASTG:    "MASTG-TEST-0048",
			Detail:   "Class and method names in the dex appear readable, so reverse engineering the logic and locating secrets costs an attacker very little. Obfuscation is a cost multiplier, not a boundary.",
			Evidence: strings.Join(info.DexFiles, ", "),
			Location: "classes.dex",
		})
	}

	sortFindings(out)
	return out
}

// severityForExportedComponent grades the exposure by what the component can do.
func severityForExportedComponent(kind string, c Component) string {
	switch kind {
	case "provider":
		// A provider is a data surface; reachable without a permission it is
		// the highest-value of the four.
		return SeverityHigh
	case "service":
		return SeverityMedium
	case "receiver":
		return SeverityMedium
	default:
		// An exported activity is common and often intentional (launcher,
		// share target); on its own it is a review item.
		return SeverityLow
	}
}

func mastgForExportedComponent(kind string) string {
	switch kind {
	case "activity":
		return "MASTG-TEST-0364"
	case "service":
		return "MASTG-TEST-0365"
	case "receiver":
		return "MASTG-TEST-0366"
	default:
		return "MASTG-TEST-0355"
	}
}

// sdkLessThan compares a manifest SDK string (which may be a codename) against a
// numeric API level. A codename cannot be ordered, so it is treated as not-less
// rather than guessed.
func sdkLessThan(v string, level int) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n < level
}

// dangerousPermissionPrefixes are the runtime-dangerous groups from the
// platform's protectionLevel classification.
var dangerousPermissionPrefixes = []string{
	"android.permission.READ_CONTACTS",
	"android.permission.WRITE_CONTACTS",
	"android.permission.READ_CALL_LOG",
	"android.permission.WRITE_CALL_LOG",
	"android.permission.READ_SMS",
	"android.permission.SEND_SMS",
	"android.permission.RECEIVE_SMS",
	"android.permission.READ_PHONE_STATE",
	"android.permission.READ_PHONE_NUMBERS",
	"android.permission.CALL_PHONE",
	"android.permission.CAMERA",
	"android.permission.RECORD_AUDIO",
	"android.permission.ACCESS_FINE_LOCATION",
	"android.permission.ACCESS_COARSE_LOCATION",
	"android.permission.ACCESS_BACKGROUND_LOCATION",
	"android.permission.READ_EXTERNAL_STORAGE",
	"android.permission.WRITE_EXTERNAL_STORAGE",
	"android.permission.MANAGE_EXTERNAL_STORAGE",
	"android.permission.BODY_SENSORS",
	"android.permission.ACTIVITY_RECOGNITION",
	"android.permission.POST_NOTIFICATIONS",
	"android.permission.READ_MEDIA_IMAGES",
	"android.permission.READ_MEDIA_VIDEO",
	"android.permission.READ_MEDIA_AUDIO",
	"android.permission.BLUETOOTH_SCAN",
	"android.permission.BLUETOOTH_CONNECT",
	"android.permission.QUERY_ALL_PACKAGES",
	"android.permission.SYSTEM_ALERT_WINDOW",
	"android.permission.REQUEST_INSTALL_PACKAGES",
	"android.permission.BIND_ACCESSIBILITY_SERVICE",
}

func isDangerousPermission(name string) bool {
	for _, p := range dangerousPermissionPrefixes {
		if name == p {
			return true
		}
	}
	return false
}

// IsDangerousPermission reports whether a permission belongs to a runtime
// -dangerous group, for callers outside the package.
func IsDangerousPermission(name string) bool { return isDangerousPermission(name) }

func shortPermission(name string) string {
	return strings.TrimPrefix(name, "android.permission.")
}

func limitSlice(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// sortFindings imposes a total order so the tool output is byte-identical for
// identical input. Severity first (so the operator reads what matters), then
// class, then location.
func sortFindings(fs []Finding) {
	rank := map[string]int{
		SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2,
		SeverityLow: 3, SeverityInfo: 4,
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := rank[a.Severity], rank[b.Severity]; ra != rb {
			return ra < rb
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Title < b.Title
	})
}

// secretPatterns are the credential shapes worth surfacing from an APK. Each is
// anchored on a provider-specific prefix rather than a generic "high entropy"
// heuristic: a false positive here costs an operator real time, and the tokens
// below have unambiguous formats.
var secretPatterns = []struct {
	class    string
	name     string
	re       *regexp.Regexp
	masvs    string
	mastg    string
	severity string
}{
	{
		class: "hardcoded_secret", name: "Google API key",
		re:    regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityHigh,
	},
	{
		class: "hardcoded_secret", name: "AWS access key id",
		re:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityHigh,
	},
	{
		class: "hardcoded_secret", name: "Firebase database URL",
		re:    regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityMedium,
	},
	{
		class: "hardcoded_secret", name: "Stripe secret key",
		re:    regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityCritical,
	},
	{
		class: "hardcoded_secret", name: "JSON Web Token",
		re:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityMedium,
	},
	{
		class: "hardcoded_secret", name: "Private key block",
		re:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityCritical,
	},
	{
		class: "hardcoded_secret", name: "Basic auth credentials in a URL",
		re:    regexp.MustCompile(`https?://[^\s/:@]+:[^\s/@]{6,}@`),
		masvs: "MASVS-STORAGE-1", mastg: "MASTG-TEST-0001", severity: SeverityMedium,
	},
}

// ScanSecrets runs the credential patterns over free text and returns findings.
// The text is expected to come from the package's string pool or from
// decompiled sources; the caller supplies where it came from as origin.
//
// Matches are redacted in the evidence: a report that contains a live production
// key in full is itself a leak, so only a prefix and the length are kept.
func ScanSecrets(text, origin string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAllString(text, 5) {
			key := p.class + "|" + p.name + "|" + origin
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Finding{
				Class:    p.class,
				Title:    fmt.Sprintf("Hardcoded credential in package: %s", p.name),
				Severity: p.severity,
				MASVS:    p.masvs,
				MASTG:    p.mastg,
				Detail:   "A credential-shaped string is embedded in the package. Anything shipped in an APK is readable by anyone who installs it, so the value must be treated as public and revoked.",
				Evidence: fmt.Sprintf("%s: %s", origin, redact(m)),
				Location: origin,
			})
		}
	}
	return out
}

// redact keeps enough of a match to identify it without reproducing the secret.
func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:6] + "…(" + fmt.Sprint(len(s)) + " chars)"
}
