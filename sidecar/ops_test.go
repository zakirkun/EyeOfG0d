package main

import (
	"strings"
	"testing"
)

func TestValidateLaunchAcceptsRealRequests(t *testing.T) {
	// These are the shapes the mobile-apk skill's dynamic stage needs.
	cases := []struct {
		name string
		in   LaunchRequest
		want string
	}{
		{
			name: "exported activity with string extra",
			in: LaunchRequest{
				Component: "com.target.app/.AdminActivity",
				Extras:    map[string]string{"url": "https://attacker.test/x"},
			},
			want: "com.target.app/com.target.app.AdminActivity",
		},
		{
			name: "fully qualified class",
			in:   LaunchRequest{Component: "com.target.app/com.target.app.ui.Share"},
			want: "com.target.app/com.target.app.ui.Share",
		},
		{
			name: "inner class with dollar",
			in:   LaunchRequest{Component: "com.target.app/com.target.app.Outer$Inner"},
			want: "com.target.app/com.target.app.Outer$Inner",
		},
		{
			name: "service with action",
			in: LaunchRequest{
				Component: "com.target.app/.SyncService",
				Kind:      "service",
				Action:    "com.target.app.SYNC",
			},
			want: "com.target.app/com.target.app.SyncService",
		},
		{
			name: "broadcast with data uri",
			in: LaunchRequest{
				Component: "com.target.app/.Receiver",
				Kind:      "broadcast",
				Data:      "content://com.target.app.provider/secret",
			},
			want: "com.target.app/com.target.app.Receiver",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateLaunch(tc.in)
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			if got.Component != tc.want {
				t.Fatalf("component = %q, want %q", got.Component, tc.want)
			}
		})
	}
}

func TestValidateLaunchDefaultsToActivity(t *testing.T) {
	got, err := validateLaunch(LaunchRequest{Component: "a.b/.C"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "activity" {
		t.Fatalf("kind = %q, want activity", got.Kind)
	}
}

func TestValidateLaunchRejectsInjectionAndMalformedInput(t *testing.T) {
	// Every case here must be refused rather than escaped: a rejected request
	// cannot become an argument, so there is nothing to neutralise.
	cases := []struct {
		name string
		in   LaunchRequest
	}{
		{"no slash", LaunchRequest{Component: "com.target.app"}},
		{"empty package", LaunchRequest{Component: "/.X"}},
		{"empty class", LaunchRequest{Component: "com.target.app/"}},
		{"shell metachar semicolon", LaunchRequest{Component: "com.target.app/.X;rm -rf /"}},
		{"shell metachar pipe", LaunchRequest{Component: "a.b/.C|id"}},
		{"backtick", LaunchRequest{Component: "a.b/.C`id`"}},
		{"dollar substitution", LaunchRequest{Component: "a.b/.C$(id)"}},
		{"space in class", LaunchRequest{Component: "a.b/.C D"}},
		{"newline in class", LaunchRequest{Component: "a.b/.C\nD"}},
		{"quote in class", LaunchRequest{Component: `a.b/.C"D`}},
		{"leading digit package", LaunchRequest{Component: "1com/.X"}},
		{"traversal class", LaunchRequest{Component: "a.b/../../etc/passwd"}},
		{"bad kind", LaunchRequest{Component: "a.b/.C", Kind: "root"}},
		{"bad action", LaunchRequest{Component: "a.b/.C", Action: "x y"}},
		{"action with semicolon", LaunchRequest{Component: "a.b/.C", Action: "a;id"}},
		{"data with newline", LaunchRequest{Component: "a.b/.C", Data: "http://x/\ny"}},
		{"data with NUL", LaunchRequest{Component: "a.b/.C", Data: "http://x/\x00"}},
		{"bad extra key", LaunchRequest{Component: "a.b/.C", Extras: map[string]string{"a b": "v"}}},
		{"extra key starting digit", LaunchRequest{Component: "a.b/.C", Extras: map[string]string{"1a": "v"}}},
		{"extra value with newline", LaunchRequest{Component: "a.b/.C", Extras: map[string]string{"a": "x\ny"}}},
		{"extra value with NUL", LaunchRequest{Component: "a.b/.C", Extras: map[string]string{"a": "x\x00y"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateLaunch(tc.in); err == nil {
				t.Fatalf("accepted unsafe input: %+v", tc.in)
			}
		})
	}
}

func TestValidateLaunchBoundsExtras(t *testing.T) {
	tooMany := make(map[string]string, maxExtras+1)
	for i := 0; i <= maxExtras; i++ {
		tooMany[string(rune('a'+i))] = "v"
	}
	if _, err := validateLaunch(LaunchRequest{Component: "a.b/.C", Extras: tooMany}); err == nil {
		t.Fatal("accepted more extras than the bound")
	}

	long := strings.Repeat("x", maxValue+1)
	if _, err := validateLaunch(LaunchRequest{Component: "a.b/.C", Extras: map[string]string{"a": long}}); err == nil {
		t.Fatal("accepted an extra value over the bound")
	}
}

func TestValidTextAllowsSpacesButNotControlCharacters(t *testing.T) {
	if !validText("select * from users where x=1", 100) {
		t.Fatal("rejected ordinary text with spaces")
	}
	for _, bad := range []string{"a\x00b", "a\nb", "a\rb", "a\tb", "a\x1bb", "a\x7fb"} {
		if validText(bad, 100) {
			t.Fatalf("accepted control characters: %q", bad)
		}
	}
	if validText(strings.Repeat("x", 11), 10) {
		t.Fatal("accepted text over the limit")
	}
	// Invalid UTF-8 must not reach adb's argv.
	if validText(string([]byte{0xff, 0xfe}), 10) {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestLaunchArgsAreFixedAndOrdered(t *testing.T) {
	req, err := validateLaunch(LaunchRequest{
		Component: "com.target.app/.Admin",
		Action:    "android.intent.action.VIEW",
		Data:      "https://attacker.test/x",
		Extras:    map[string]string{"zeta": "2", "alpha": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	args := launchArgs(req)
	want := []string{
		"shell", "am", "start",
		"-n", "com.target.app/com.target.app.Admin",
		"-a", "android.intent.action.VIEW",
		"-d", "https://attacker.test/x",
		"--es", "alpha", "1",
		"--es", "zeta", "2",
	}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q (full: %#v)", i, args[i], want[i], args)
		}
	}
}

func TestLaunchArgsUseTheRightAmSubcommand(t *testing.T) {
	for kind, sub := range map[string]string{
		"activity":  "start",
		"service":   "startservice",
		"broadcast": "broadcast",
	} {
		req, err := validateLaunch(LaunchRequest{Component: "a.b/.C", Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		args := launchArgs(req)
		if len(args) < 3 || args[2] != sub {
			t.Fatalf("kind %q produced %#v, want subcommand %q", kind, args, sub)
		}
	}
}

func TestLaunchArgsNeverContainAShell(t *testing.T) {
	req, err := validateLaunch(LaunchRequest{
		Component: "com.target.app/.X",
		Extras:    map[string]string{"cmd": "id; uname -a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := launchArgs(req)
	// The value is one argv element, so its punctuation is data, not syntax.
	for i, a := range args {
		if a == ";" || a == "sh" || a == "-c" {
			t.Fatalf("argv[%d] = %q looks like a shell invocation: %#v", i, a, args)
		}
	}
	if args[len(args)-1] != "id; uname -a" {
		t.Fatalf("extra value was split or mangled: %#v", args)
	}
}

// The KVM gate must not be satisfiable by text that merely mentions KVM. The
// emulator's own failure messages name KVM, so a substring check reports
// acceleration as usable on a host where it is not — and the boot then fails
// later with a reason that hides the real cause.
func TestAccelUsable(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "real success output",
			out:  "accel:\n0\nKVM (version 12) is installed and usable.\naccel\n",
			want: true,
		},
		{
			name: "success with crlf and leading space",
			out:  "accel:\r\n 0\r\nKVM (version 12) is installed and usable.\r\naccel\r\n",
			want: true,
		},
		{
			name: "not accessible mentions kvm but is not usable",
			out:  "accel:\n1\nKVM is installed but not accessible.\naccel\n",
			want: false,
		},
		{
			name: "cpu without virtualisation",
			out:  "accel:\n1\nKVM requires a CPU that supports vmx or svm\naccel\n",
			want: false,
		},
		{
			name: "no accel block at all",
			out:  "This machine does not support any acceleration.\n",
			want: false,
		},
		{
			name: "status zero but no usable wording",
			out:  "accel:\n0\naccel\n",
			want: false,
		},
		{
			name: "empty",
			out:  "",
			want: false,
		},
	}
	for _, c := range cases {
		if got := accelUsable(c.out); got != c.want {
			t.Errorf("%s: accelUsable = %v, want %v", c.name, got, c.want)
		}
	}
}
