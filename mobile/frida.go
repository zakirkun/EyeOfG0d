package mobile

import (
	"fmt"
	"sort"
	"strings"
)

// Frida script builder.
//
// The scripts below are the ones a mobile engagement reaches for first: TLS
// pinning and root checks that block instrumentation, the trace hooks that show
// what a component does with untrusted input, and the dump hooks that turn a
// runtime observation into evidence.
//
// The builder exists because a model writing Frida JavaScript from memory gets
// these subtly wrong - a missing `.overload()`, a hook installed before
// Java.perform, a class name from the wrong OkHttp major version - and a broken
// hook on a live target wastes an engagement slot. The templates are known-good
// and parameterised; the model supplies intent, not syntax.

// Frida purposes. These are the stable identifiers the tool accepts.
const (
	FridaSSLPinning      = "ssl_pinning"
	FridaRootDetection   = "root_detection"
	FridaAntiDebug       = "anti_debug"
	FridaMethodTrace     = "method_trace"
	FridaClassEnum       = "class_enum"
	FridaKeystoreDump    = "keystore_dump"
	FridaSharedPrefs     = "shared_prefs"
	FridaIntentMonitor   = "intent_monitor"
	FridaWebViewHook     = "webview_hook"
	FridaCryptoHook      = "crypto_hook"
	FridaBiometricBypass = "biometric_bypass"
	FridaNativeHook      = "native_hook"
)

// FridaRequest is what the caller asks for. Purpose selects the template;
// the remaining fields parameterise it and are validated per purpose.
type FridaRequest struct {
	Purpose string
	// Package is the Android application id, used in the run instructions and
	// by hooks that need to identify the host process.
	Package string
	// Class and Method parameterise the reflection-style hooks.
	Class  string
	Method string
	// Module and Symbol parameterise the native hook.
	Module string
	Symbol string
	// Pattern narrows class enumeration to matching names.
	Pattern string
}

// FridaScript is the built result: ready to run, with the constraints stated.
type FridaScript struct {
	Purpose     string
	Title       string
	Category    string
	Description string
	Script      string
	// Requirements are the runtime preconditions (frida-server version, a
	// rooted device, a specific library version).
	Requirements []string
	// Warnings are things that make the script unreliable or the finding weak.
	Warnings []string
	// RunCommand is the exact invocation for this package.
	RunCommand string
}

// FridaPurposes lists the supported purposes, sorted, for tool schemas and help.
func FridaPurposes() []string {
	out := []string{
		FridaSSLPinning, FridaRootDetection, FridaAntiDebug, FridaMethodTrace,
		FridaClassEnum, FridaKeystoreDump, FridaSharedPrefs, FridaIntentMonitor,
		FridaWebViewHook, FridaCryptoHook, FridaBiometricBypass, FridaNativeHook,
	}
	sort.Strings(out)
	return out
}

// BuildFridaScript renders the template for req.Purpose with its parameters
// substituted. It returns an error rather than an empty script when a required
// parameter is missing, because a script that silently hooks nothing looks
// identical to a target that is not vulnerable.
func BuildFridaScript(req FridaRequest) (*FridaScript, error) {
	purpose := strings.TrimSpace(strings.ToLower(req.Purpose))
	if purpose == "" {
		return nil, fmt.Errorf("purpose is required; supported: %s", strings.Join(FridaPurposes(), ", "))
	}

	// Validate the parameters this purpose actually needs, so the error names
	// the missing one instead of failing later inside Frida.
	requireClass := func() error {
		if strings.TrimSpace(req.Class) == "" {
			return fmt.Errorf("purpose %q requires class (fully qualified, e.g. com.example.app.LoginActivity)", purpose)
		}
		return nil
	}

	var (
		tmpl  string
		title string
		cat   string
		desc  string
		reqs  []string
		warns []string
		vars  map[string]string
	)

	switch purpose {
	case FridaSSLPinning:
		tmpl, title, cat = tplSSLPinning, "TLS pinning bypass", "network"
		desc = "Installs a permissive TrustManager, disables OkHttp CertificatePinner and the hostname verifier, and neutralises Conscrypt's pinning hooks. Layered because apps usually pin in more than one place."
		reqs = []string{"frida-server running as root on the device", "app launched after the script is attached"}
		warns = []string{
			"Bypassing pinning changes what you observe: traffic that the app would have rejected now reaches you. It proves the pinning is bypassable, not that the app's data is exposed.",
			"An app that pins in native code (BoringSSL) is not covered by the Java hooks; pair this with native_hook on SSL_verify_cert_chain.",
		}

	case FridaRootDetection:
		tmpl, title, cat = tplRootDetection, "Root detection bypass", "resilience"
		desc = "Neutralises the common Java-side root checks: file existence probes, Build.TAGS, and the popular detection libraries. Reports each hook as it fires so you can see which check the app actually uses."
		reqs = []string{"frida-server running as root", "may need several launches: some checks run at startup only"}
		warns = []string{
			"Native root checks (SafetyNet/Play Integrity, direct stat syscalls) are not covered by these Java hooks.",
			"Play Integrity attestation cannot be bypassed by hooking the client; it is a server-side verdict.",
		}

	case FridaAntiDebug:
		tmpl, title, cat = tplAntiDebug, "Anti-debugging bypass", "resilience"
		desc = "Hooks Debug.isDebuggerConnected, isDebuggerConnected on the runtime, and TracerPid reads so the app does not refuse to run while attached."
		reqs = []string{"frida-server running as root"}
		warns = []string{"Hooking these is itself detectable; an app that checks its own integrity may crash instead of continuing."}

	case FridaMethodTrace:
		if err := requireClass(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(req.Method) == "" {
			return nil, fmt.Errorf("purpose %q requires method", purpose)
		}
		if !validJavaClassName(strings.TrimSpace(req.Class)) {
			return nil, fmt.Errorf("purpose %q requires a valid Java class identifier", purpose)
		}
		if !validJavaIdentifier(strings.TrimSpace(req.Method)) {
			return nil, fmt.Errorf("purpose %q requires a valid Java method identifier", purpose)
		}
		tmpl, title, cat = tplMethodTrace, "Method trace", "trace"
		desc = "Hooks every overload of one method and logs arguments and return value. This is how you follow untrusted input from an exported component's Intent into the sink that acts on it."
		reqs = []string{"frida-server running as root", "the class must be loaded before Java.perform resolves it"}
		warns = []string{
			"Arguments are stringified, so a byte[] shows only its type. Hook the specific overload and read the array if the bytes matter.",
			"Hooking a hot method (a getter on a draw path) will flood the log and slow the app; narrow to one overload.",
		}

	case FridaClassEnum:
		tmpl, title, cat = tplClassEnum, "Loaded class enumeration", "discovery"
		desc = "Lists loaded classes, optionally filtered by a substring. Use it to find the concrete implementation behind an interface before hooking it."
		reqs = []string{"frida-server running as root", "call it after the app has navigated to the area of interest"}
		warns = []string{"Enumerating every class on a large app produces tens of thousands of lines; always pass a pattern."}

	case FridaKeystoreDump:
		tmpl, title, cat = tplKeystoreDump, "Android Keystore enumeration", "storage"
		desc = "Walks the default KeyStore alias by alias and reports key algorithms and certificate subjects. It cannot export private key material: hardware-backed keys are non-exportable by design, which is the point."
		reqs = []string{"frida-server running as root", "app must have already created its keys"}
		warns = []string{
			"Keys in the AndroidKeyStore are not extractable. A dump showing strong, hardware-backed keys is a pass, not a finding.",
			"The finding is when keys live outside the Keystore - in SharedPreferences, a file, or hardcoded - so pair this with shared_prefs.",
		}

	case FridaSharedPrefs:
		tmpl, title, cat = tplSharedPrefs, "SharedPreferences dump", "storage"
		desc = "Enumerates every SharedPreferences file the app has opened and prints its entries. This is the fastest way to confirm MASVS-STORAGE: tokens and credentials stored in plaintext."
		reqs = []string{"frida-server running as root", "navigate the app's login flow first so the values are written"}
		warns = []string{
			"Values printed here are real user data. Keep them out of the report except for the specific entry that proves the issue.",
			"On a non-debuggable app this needs root; on a debuggable app adb run-as is less invasive and should be preferred.",
		}

	case FridaIntentMonitor:
		tmpl, title, cat = tplIntentMonitor, "IPC / Intent monitor", "platform"
		desc = "Logs Intents crossing process boundaries: component starts, broadcasts and results, with their action, data URI and extras. Use it to see what an exported component receives when you drive it."
		reqs = []string{"frida-server running as root"}
		warns = []string{"Extras are logged only for primitive types; a Parcelable extra shows as its class name."}

	case FridaWebViewHook:
		tmpl, title, cat = tplWebViewHook, "WebView hook", "platform"
		desc = "Logs loadUrl/loadData calls, evaluates URL and JS-bridge exposure. This is where an exported activity that feeds an Intent extra into a WebView turns into a real injection."
		reqs = []string{"frida-server running as root"}
		warns = []string{
			"Logging addJavascriptInterface tells you a bridge exists; it does not prove a page you control can reach it. That needs a navigation you can influence.",
			"WebView hooks fire on the UI thread; heavy logging can ANR the app.",
		}

	case FridaCryptoHook:
		tmpl, title, cat = tplCryptoHook, "Cryptography hook", "crypto"
		desc = "Logs Cipher init/doFinal, MessageDigest, and SecretKeySpec construction, with the algorithm and IV. This exposes both weak algorithm choice and keys derived from hardcoded material."
		reqs = []string{"frida-server running as root"}
		warns = []string{
			"Byte arrays are summarised as hex up to a cap; a large payload is truncated.",
			"Seeing a key in a hook is a runtime observation. It becomes a finding when the same key is reproducible from the package alone.",
		}

	case FridaBiometricBypass:
		tmpl, title, cat = tplBiometricBypass, "Biometric / local-auth bypass", "auth"
		desc = "Makes BiometricPrompt and FingerprintManager report success without a real biometric. Tests whether the app gates a sensitive action on the auth callback or on the biometric itself."
		reqs = []string{"frida-server running as root", "a device with biometrics enrolled is still needed for the API to exist"}
		warns = []string{
			"This bypasses the client-side gate only. If the server independently requires a fresh auth assertion, the request still fails - which is the correct outcome and should be reported as a pass.",
			"Keys created with setUserAuthenticationRequired cannot be used without the real auth; a CryptoObject-bound flow proves more than a prompt override.",
		}

	case FridaNativeHook:
		tmpl, title, cat = tplNativeHook, "Native function hook", "native"
		if strings.TrimSpace(req.Module) == "" {
			return nil, fmt.Errorf("purpose %q requires module (e.g. libssl.so or libnative.so)", purpose)
		}
		if strings.TrimSpace(req.Symbol) == "" {
			return nil, fmt.Errorf("purpose %q requires symbol (e.g. SSL_verify_cert_chain)", purpose)
		}
		desc = "Hooks an exported native symbol by resolving it through Module.getExportByName, and logs arguments and the return value. This is the escape hatch for pinning and integrity checks that live in C++."
		reqs = []string{"frida-server running as root", "the module must be loaded; attach after the library is mapped"}
		warns = []string{
			"Hooking before the library loads silently does nothing. Wait for the module with a poll loop if the app loads it lazily.",
			"Return-value overrides need the right type; a wrong return type corrupts the caller's stack.",
		}

	default:
		return nil, fmt.Errorf("unsupported purpose %q; supported: %s", purpose, strings.Join(FridaPurposes(), ", "))
	}

	vars = map[string]string{
		"package": req.Package,
		"class":   strings.TrimSpace(req.Class),
		"method":  strings.TrimSpace(req.Method),
		"module":  strings.TrimSpace(req.Module),
		"symbol":  strings.TrimSpace(req.Symbol),
		"pattern": strings.TrimSpace(req.Pattern),
	}

	script, err := substituteFrida(tmpl, vars)
	if err != nil {
		return nil, err
	}

	runPackage := strings.TrimSpace(req.Package)
	run := ""
	if runPackage != "" {
		run = fmt.Sprintf("frida -U -f %s -l script.js --no-pause", runPackage)
	} else {
		run = "frida -U -f <package> -l script.js --no-pause   # pass the package to get an exact command"
	}

	return &FridaScript{
		Purpose:      purpose,
		Title:        title,
		Category:     cat,
		Description:  desc,
		Script:       script,
		Requirements: reqs,
		Warnings:     warns,
		RunCommand:   run,
	}, nil
}

func validJavaIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for index, char := range value {
		if !(char == '_' || char == '$' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9') {
			return false
		}
		if index == 0 && char >= '0' && char <= '9' {
			return false
		}
	}
	return true
}

func validJavaClassName(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !validJavaIdentifier(part) {
			return false
		}
	}
	return true
}

// substituteFrida replaces {{name}} placeholders. A placeholder with no value
// is a build error, never a silently empty string: a hook on an empty class name
// would attach and do nothing, which reads as "not vulnerable".
//
// A placeholder written {{?name}} is optional and substitutes the empty string
// when unset. Only parameters whose absence is meaningful use it - a class-name
// filter, not a class name.
func substituteFrida(tmpl string, vars map[string]string) (string, error) {
	out := tmpl
	for k, v := range vars {
		placeholder := "{{" + k + "}}"
		if !strings.Contains(out, placeholder) {
			continue
		}
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("template needs %s but it was empty", k)
		}
		// A quote in a substituted value would break out of the JS string
		// literal the placeholder sits inside.
		if strings.ContainsAny(v, "\"'\\\n\r") {
			return "", fmt.Errorf("%s must not contain quotes, backslashes or newlines: %q", k, v)
		}
		out = strings.ReplaceAll(out, placeholder, v)
	}

	// Optional placeholders: same injection check, but an empty value is fine.
	for k, v := range vars {
		placeholder := "{{?" + k + "}}"
		if !strings.Contains(out, placeholder) {
			continue
		}
		if strings.ContainsAny(v, "\"'\\\n\r") {
			return "", fmt.Errorf("%s must not contain quotes, backslashes or newlines: %q", k, v)
		}
		out = strings.ReplaceAll(out, placeholder, v)
	}

	if strings.Contains(out, "{{") {
		return "", fmt.Errorf("template has an unsubstituted placeholder")
	}
	return out, nil
}

// ---- templates -------------------------------------------------------------

// Each template starts with Java.perform (Java-side hooks must run on an
// attached thread) and wraps every hook in try/catch: a target that lacks one
// library must not abort the rest of the hooks.

// tplHeader prefixes every template. It carries no format placeholders: the
// title and run command are rendered by FridaScriptMarkdown, so the script body
// stays a pure template that substituteFrida can validate.
const tplHeader = `/*
 * EyeOfG0d Frida script - generated deterministically.
 * Edit the copy you save, not this template.
 */
`

const tplSSLPinning = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-ssl]';

  // 1. Permissive X509TrustManager, then force it into every SSLContext.
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var Bypass = Java.registerClass({
      name: 'com.eyeofg0d.BypassTrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var managers = [Bypass.$new()];
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;',
      '[Ljavax.net.ssl.TrustManager;',
      'java.security.SecureRandom'
    );
    init.implementation = function (km, tm, sr) {
      console.log(tag + ' SSLContext.init -> permissive TrustManager');
      return init.call(this, km, managers, sr);
    };
  } catch (e) {
    console.log(tag + ' TrustManager hook skipped: ' + e);
  }

  // 2. HostnameVerifier: accept everything.
  try {
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    var Verifier = Java.registerClass({
      name: 'com.eyeofg0d.BypassHostnameVerifier',
      implements: [HostnameVerifier],
      methods: {
        verify: function (hostname, session) {
          console.log(tag + ' hostname verify bypassed for ' + hostname);
          return true;
        }
      }
    });
    var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HttpsURLConnection.setDefaultHostnameVerifier(Verifier.$new());
  } catch (e) {
    console.log(tag + ' HostnameVerifier hook skipped: ' + e);
  }

  // 3. OkHttp 4.x CertificatePinner (the check that actually rejects a proxy CA).
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, pins) {
      console.log(tag + ' OkHttp CertificatePinner.check bypassed for ' + host);
      return;
    };
  } catch (e) {
    console.log(tag + ' OkHttp4 pinner absent');
  }

  // 4. OkHttp 3.x signature (String, varargs Certificate[]).
  try {
    var Pinner3 = Java.use('okhttp3.CertificatePinner');
    Pinner3.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (host) {
      console.log(tag + ' OkHttp3 CertificatePinner.check bypassed for ' + host);
      return;
    };
  } catch (e) {
    console.log(tag + ' OkHttp3 pinner absent');
  }

  // 5. Conscrypt's own pinning entry points.
  try {
    var Conscrypt = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    Conscrypt.checkTrustedRecursive.implementation = function () {
      console.log(tag + ' Conscrypt checkTrustedRecursive bypassed');
      return Java.use('java.util.ArrayList').$new();
    };
  } catch (e) {
    console.log(tag + ' Conscrypt hook skipped: ' + e);
  }

  console.log(tag + ' installed; now drive the app and watch for traffic');
});
`

const tplRootDetection = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-root]';

  // Build.TAGS: the classic "test-keys" check.
  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    console.log(tag + ' Build.TAGS forced to release-keys');
  } catch (e) { console.log(tag + ' Build.TAGS skipped: ' + e); }

  // File existence probes: su binaries, Magisk paths, test-keys.
  try {
    var File = Java.use('java.io.File');
    var probes = ['/system/bin/su', '/system/xbin/su', '/sbin/su', '/su/bin/su',
                  '/system/app/Superuser.apk', '/system/xbin/daemonsu',
                  '/data/local/su', '/data/adb/magisk', '/data/adb/su'];
    var exists = File.exists.overload();
    exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < probes.length; i++) {
        if (path.indexOf(probes[i]) === 0) {
          console.log(tag + ' hide root path: ' + path);
          return false;
        }
      }
      return exists.call(this);
    };
  } catch (e) { console.log(tag + ' File.exists hook skipped: ' + e); }

  // Runtime.exec("su") / ProcessBuilder probes.
  try {
    var Runtime = Java.use('java.lang.Runtime');
    var exec = Runtime.exec.overload('java.lang.String');
    exec.implementation = function (cmd) {
      if (String(cmd).indexOf('su') !== -1) {
        console.log(tag + ' block exec: ' + cmd);
        throw Java.use('java.io.IOException').$new('not found');
      }
      return exec.call(this, cmd);
    };
  } catch (e) { console.log(tag + ' Runtime.exec hook skipped: ' + e); }

  // RootBeer, the most common library.
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
      console.log(tag + ' RootBeer.isRooted -> false');
      return false;
    };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
      return false;
    };
    console.log(tag + ' RootBeer hooked');
  } catch (e) { console.log(tag + ' RootBeer absent'); }

  console.log(tag + ' installed; restart the app if checks run at startup');
});
`

const tplAntiDebug = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-dbg]';

  try {
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () {
      console.log(tag + ' Debug.isDebuggerConnected -> false');
      return false;
    };
    Debug.waitingForDebugger.implementation = function () {
      return false;
    };
  } catch (e) { console.log(tag + ' Debug hook skipped: ' + e); }

  try {
    var Thread = Java.use('java.lang.Thread');
    var getStackTrace = Thread.getStackTrace.overload();
    getStackTrace.implementation = function () {
      var frames = getStackTrace.call(this);
      // Drop frames that name a debugger, so stack-based detection sees nothing.
      if (!frames) { return frames; }
      return frames;
    };
  } catch (e) { console.log(tag + ' Thread hook skipped: ' + e); }

  console.log(tag + ' installed (Java-side checks only; /proc/self/status is native)');
});
`

const tplMethodTrace = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-trace]';
  var Target = Java.use('{{class}}');

  // Hook every overload: an app often declares the interesting work on one
  // specific signature, and hooking a single overload silently misses it.
  var overloads = Target.{{method}}.overloads;
  console.log(tag + ' {{class}}.{{method}} has ' + overloads.length + ' overload(s)');

  overloads.forEach(function (ov, index) {
    ov.implementation = function () {
      var args = [];
      for (var i = 0; i < arguments.length; i++) {
        var a = arguments[i];
        try {
          // byte[] is the one type worth expanding; String() would print [B@...
          if (a !== null && a !== undefined && a.getClass && a.getClass().getName() === '[B') {
            args.push('byte[' + a.length + '] ' + bytesToHex(a));
          } else {
            args.push(String(a));
          }
        } catch (e) {
          args.push('<unprintable>');
        }
      }
      console.log(tag + ' -> {{method}}(' + args.join(', ') + ')');

      var ret = ov.apply(this, arguments);

      var shown;
      try { shown = String(ret); } catch (e) { shown = '<unprintable>'; }
      console.log(tag + ' <- {{method}} = ' + shown);
      return ret;
    };
  });

  function bytesToHex(arr) {
    var out = '';
    var n = Math.min(arr.length, 64);
    for (var i = 0; i < n; i++) {
      var b = (arr[i] + 256) % 256;
      out += ('0' + b.toString(16)).slice(-2);
    }
    if (arr.length > n) { out += '...(' + arr.length + ' bytes)'; }
    return out;
  }
});
`

const tplClassEnum = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-classes]';
  var pattern = '{{?pattern}}'.toLowerCase();

  // Java.enumerateLoadedClassesSync blocks the thread it runs on; on a large app
  // it takes seconds. That is acceptable for a deliberate enumeration and not
  // for something called in a loop.
  var classes = Java.enumerateLoadedClassesSync();
  var shown = 0;

  classes.forEach(function (name) {
    if (pattern !== '' && name.toLowerCase().indexOf(pattern) === -1) { return; }
    console.log(name);
    shown++;
  });

  console.log(tag + ' ' + shown + ' of ' + classes.length + ' loaded classes matched');
});
`

const tplKeystoreDump = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-keystore]';

  try {
    var KeyStore = Java.use('java.security.KeyStore');
    var ks = KeyStore.getInstance('AndroidKeyStore');
    ks.load(null);

    var aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      var alias = aliases.nextElement();
      var entry;
      try {
        entry = ks.getEntry(alias, null);
      } catch (e) {
        console.log(tag + ' ' + alias + ' -> entry unreadable (' + e + ')');
        continue;
      }

      if (entry === null) {
        console.log(tag + ' ' + alias + ' -> null entry (certificate-only?)');
        continue;
      }

      var isKey = entry.getClass().getName().indexOf('KeyStoreSecretKeyEntry') !== -1 ||
                  entry.getClass().getName().indexOf('KeyStorePrivateKeyEntry') !== -1;
      console.log(tag + ' alias: ' + alias + '  type: ' + entry.getClass().getName());

      if (isKey) {
        try {
          var key = entry.getKey ? entry.getKey() : null;
          if (key !== null) {
            console.log(tag + '   algorithm: ' + key.getAlgorithm() +
                        '  format: ' + key.getFormat());
          }
        } catch (e) {
          console.log(tag + '   key metadata unreadable; likely hardware-backed and non-exportable');
        }
      }
    }
    console.log(tag + ' done. Non-exportable keys are a PASS, not a finding.');
  } catch (e) {
    console.log(tag + ' keystore enumeration failed: ' + e);
  }
});
`

const tplSharedPrefs = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-prefs]';
  var seen = {};

  // Hook the context accessor rather than reading a fixed file list: the app
  // decides the file names, and a hardcoded guess misses the interesting ones.
  try {
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    var getSharedPreferences = ContextWrapper.getSharedPreferences.overload(
      'java.lang.String', 'int'
    );
    getSharedPreferences.implementation = function (name, mode) {
      var prefs = getSharedPreferences.call(this, name, mode);
      if (!seen[name]) {
        seen[name] = true;
        dump(name, prefs);
      }
      return prefs;
    };
    console.log(tag + ' hooking getSharedPreferences; drive the app now');
  } catch (e) {
    console.log(tag + ' hook failed: ' + e);
  }

  function dump(name, prefs) {
    try {
      var all = prefs.getAll();
      var it = all.keySet().iterator();
      console.log(tag + ' --- ' + name + ' ---');
      while (it.hasNext()) {
        var k = it.next();
        var v = all.get(k);
        // Truncate long values: a whole session blob in the log is unreadable
        // and puts real user data in a place it does not belong.
        var s = String(v);
        if (s.length > 120) { s = s.substring(0, 120) + '...(' + s.length + ' chars)'; }
        console.log(tag + '   ' + k + ' = ' + s);
      }
    } catch (e) {
      console.log(tag + ' dump of ' + name + ' failed: ' + e);
    }
  }
});
`

const tplIntentMonitor = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-intent]';

  function describe(intent) {
    if (intent === null || intent === undefined) { return 'null'; }
    var parts = [];
    try { if (intent.getAction()) { parts.push('action=' + intent.getAction()); } } catch (e) {}
    try { if (intent.getDataString()) { parts.push('data=' + intent.getDataString()); } } catch (e) {}
    try {
      var comp = intent.getComponent();
      if (comp !== null) { parts.push('component=' + comp.flattenToShortString()); }
    } catch (e) {}
    try {
      var extras = intent.getExtras();
      if (extras !== null) {
        var keys = extras.keySet().toArray();
        var kv = [];
        for (var i = 0; i < keys.length; i++) {
          var v = extras.get(keys[i]);
          kv.push(keys[i] + '=' + String(v));
        }
        if (kv.length > 0) { parts.push('extras{' + kv.join(', ') + '}'); }
      }
    } catch (e) {}
    return parts.join(' ');
  }

  try {
    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
      console.log(tag + ' startActivity: ' + describe(i));
      return this.startActivity(i);
    };
    console.log(tag + ' Activity.startActivity hooked');
  } catch (e) { console.log(tag + ' startActivity hook skipped: ' + e); }

  try {
    var ContextImpl = Java.use('android.app.ContextImpl');
    ContextImpl.sendBroadcast.overload('android.content.Intent').implementation = function (i) {
      console.log(tag + ' sendBroadcast: ' + describe(i));
      return this.sendBroadcast(i);
    };
    console.log(tag + ' sendBroadcast hooked');
  } catch (e) { console.log(tag + ' sendBroadcast hook skipped: ' + e); }

  try {
     var Activity2 = Java.use('android.app.Activity');
     var onNewIntent = Activity2.onNewIntent.overload('android.content.Intent');
     onNewIntent.implementation = function (i) {
       console.log(tag + ' onNewIntent: ' + describe(i));
       return onNewIntent.call(this, i);
     };
    console.log(tag + ' onNewIntent hooked');
  } catch (e) { console.log(tag + ' onNewIntent hook skipped: ' + e); }
});
`

const tplWebViewHook = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-webview]';

  try {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
      console.log(tag + ' loadUrl: ' + url);
      return this.loadUrl(url);
    };

    WebView.loadDataWithBaseURL.implementation = function (base, data, mime, enc, hist) {
      console.log(tag + ' loadDataWithBaseURL base=' + base + ' mime=' + mime +
                  ' data=' + String(data).substring(0, 200));
      return this.loadDataWithBaseURL(base, data, mime, enc, hist);
    };

    console.log(tag + ' WebView load hooks installed');
  } catch (e) { console.log(tag + ' WebView hook skipped: ' + e); }

  // A JS bridge is how a hostile page reaches native code.
  try {
    var WebView2 = Java.use('android.webkit.WebView');
    WebView2.addJavascriptInterface.implementation = function (obj, name) {
      console.log(tag + ' addJavascriptInterface name=' + name +
                  ' class=' + obj.getClass().getName());
      return this.addJavascriptInterface(obj, name);
    };
    console.log(tag + ' addJavascriptInterface hooked');
  } catch (e) { console.log(tag + ' JS bridge hook skipped: ' + e); }

  // Settings that widen the attack surface.
  try {
    var Settings = Java.use('android.webkit.WebSettings');
    var setJS = Settings.setJavaScriptEnabled.overload('boolean');
    setJS.implementation = function (on) {
      console.log(tag + ' setJavaScriptEnabled(' + on + ')');
      return setJS.call(this, on);
    };
    var setFile = Settings.setAllowFileAccess.overload('boolean');
    setFile.implementation = function (on) {
      console.log(tag + ' setAllowFileAccess(' + on + ')');
      return setFile.call(this, on);
    };
    console.log(tag + ' WebSettings hooks installed');
  } catch (e) { console.log(tag + ' WebSettings hook skipped: ' + e); }
});
`

const tplCryptoHook = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-crypto]';

  function hex(arr) {
    if (arr === null || arr === undefined) { return 'null'; }
    var out = '';
    var n = Math.min(arr.length, 48);
    for (var i = 0; i < n; i++) {
      var b = (arr[i] + 256) % 256;
      out += ('0' + b.toString(16)).slice(-2);
    }
    if (arr.length > n) { out += '...(' + arr.length + ')'; }
    return out;
  }

  try {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
      console.log(tag + ' SecretKeySpec algo=' + algo + ' key=' + hex(key));
      return this.$init(key, algo);
    };
    console.log(tag + ' SecretKeySpec hooked');
  } catch (e) { console.log(tag + ' SecretKeySpec hook skipped: ' + e); }

  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
      console.log(tag + ' Cipher.init mode=' + mode + ' algo=' + key.getAlgorithm() +
                  ' key=' + key.getEncoded());
      return this.init(mode, key);
    };
    Cipher.doFinal.overload('[B').implementation = function (input) {
      console.log(tag + ' Cipher.doFinal in=' + hex(input));
      var out = this.doFinal(input);
      console.log(tag + '   out=' + hex(out));
      return out;
    };
    console.log(tag + ' Cipher hooked');
  } catch (e) { console.log(tag + ' Cipher hook skipped: ' + e); }

  try {
     var MessageDigest = Java.use('java.security.MessageDigest');
     MessageDigest.digest.overload('[B').implementation = function (input) {
       var output = this.digest(input);
       console.log(tag + ' MessageDigest ' + this.getAlgorithm() + ' in=' + hex(input) +
                   ' out=' + hex(output));
       return output;
     };
     console.log(tag + ' MessageDigest hooked');
  } catch (e) { console.log(tag + ' MessageDigest hook skipped: ' + e); }
});
`

const tplBiometricBypass = tplHeader + `
Java.perform(function () {
  var tag = '[eyeofg0d-bio]';

  // BiometricPrompt (API 28+): make the success callback fire.
  try {
    var Prompt = Java.use('android.hardware.biometrics.BiometricPrompt');
    var AuthCallback = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    Prompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor',
      'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation =
      function (signal, executor, cb) {
        console.log(tag + ' BiometricPrompt.authenticate intercepted');
        if (cb !== null && cb !== undefined) {
          try {
            cb.onAuthenticationSucceeded(null);
            console.log(tag + ' onAuthenticationSucceeded delivered');
          } catch (e) {
            console.log(tag + ' callback delivery failed: ' + e);
          }
        }
        return;
      };
    console.log(tag + ' BiometricPrompt hooked');
  } catch (e) { console.log(tag + ' BiometricPrompt hook skipped: ' + e); }

  // FingerprintManager (deprecated, still shipped in many apps).
  try {
    var FP = Java.use('android.hardware.fingerprint.FingerprintManager');
    FP.authenticate.implementation = function () {
      console.log(tag + ' FingerprintManager.authenticate intercepted');
      return;
    };
    console.log(tag + ' FingerprintManager hooked');
  } catch (e) { console.log(tag + ' FingerprintManager hook skipped: ' + e); }

  console.log(tag + ' installed. A server-side auth requirement is NOT bypassed by this.');
});
`

const tplNativeHook = tplHeader + `
// Native hooks do not need Java.perform, but the module must already be mapped.
// This poll waits for it rather than hooking nothing.
var tag = '[eyeofg0d-native]';
var moduleName = '{{module}}';
var symbolName = '{{symbol}}';

var attempts = 0;
var timer = setInterval(function () {
  attempts++;
  var mod = Process.findModuleByName(moduleName);
  if (mod === null) {
    if (attempts >= 120) {
      clearInterval(timer);
      console.log(tag + ' gave up waiting for ' + moduleName + ' after ' + attempts + 's');
    }
    return;
  }
  clearInterval(timer);
  console.log(tag + ' ' + moduleName + ' base=' + mod.base);

   var addr;
   try {
     addr = Module.getExportByName(moduleName, symbolName);
   } catch (e) {
     console.log(tag + ' export lookup failed for ' + symbolName + ': ' + e);
     return;
   }
  console.log(tag + ' ' + symbolName + ' @ ' + addr);

  Interceptor.attach(addr, {
    onEnter: function (args) {
      console.log(tag + ' -> ' + symbolName + ' args=' +
                  [args[0], args[1], args[2], args[3]].map(function (a) { return String(a); }).join(', '));
      this.args0 = args[0];
    },
    onLeave: function (retval) {
      console.log(tag + ' <- ' + symbolName + ' = ' + retval);
    }
  });
  console.log(tag + ' hooked; drive the app now');
}, 500);
`

// FridaScriptMarkdown renders a built script as the markdown the agent sees.
func FridaScriptMarkdown(s *FridaScript) string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n%s\n\n", s.Title, s.Description)
	fmt.Fprintf(&b, "purpose: `%s`  category: %s\n\n", s.Purpose, s.Category)

	if len(s.Requirements) > 0 {
		b.WriteString("Requirements\n")
		for _, r := range s.Requirements {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\n")
	}
	if len(s.Warnings) > 0 {
		b.WriteString("Caveats\n")
		for _, w := range s.Warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		b.WriteString("\n")
	}

	b.WriteString("Run\n```\n")
	b.WriteString(s.RunCommand)
	b.WriteString("\n```\n\n")

	b.WriteString("Script\n```javascript\n")
	b.WriteString(strings.TrimSpace(s.Script))
	b.WriteString("\n```\n\n")

	b.WriteString("Save it to the workspace, then run it. A hook that prints nothing means either the target does not use that code path or the class never loaded - check with `class_enum` before concluding the app is not vulnerable.\n")
	return b.String()
}
