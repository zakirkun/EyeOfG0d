package mobile

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Dex string extraction.
//
// A dex file starts with the "dex\n035" magic followed by a header whose string
// table is described by string_ids_off / string_ids_size: an array of offsets,
// each pointing at a uleb128-encoded utf-16 length followed by modified-UTF-8
// bytes. Reading that table gives every string literal and identifier in the
// package, which is where hardcoded credentials and endpoint URLs live, without
// decompiling any method body.
//
// This is intentionally not a full dex parser: only the string table is read,
// because that is the only part the checks consume.

const dexMagic = "dex\n"

// dexStrings returns the strings from one dex file, up to limit entries.
//
// A malformed header ends the read for that file rather than failing the whole
// analysis: a package with one truncated dex is still worth the strings the
// other files yield.
func dexStrings(data []byte, limit int) []string {
	if len(data) < 0x70 || !bytes.HasPrefix(data, []byte(dexMagic)) {
		return nil
	}
	// Header layout (offsets from dex_format.h):
	//   0x38 string_ids_size (u32), 0x3c string_ids_off (u32)
	stringIDsSize := binary.LittleEndian.Uint32(data[0x38:0x3c])
	stringIDsOff := binary.LittleEndian.Uint32(data[0x3c:0x40])
	if stringIDsSize == 0 || stringIDsOff == 0 {
		return nil
	}
	if int(stringIDsSize) > limit {
		stringIDsSize = uint32(limit)
	}
	if int64(stringIDsOff)+int64(stringIDsSize)*4 > int64(len(data)) {
		return nil
	}

	out := make([]string, 0, stringIDsSize)
	for i := uint32(0); i < stringIDsSize; i++ {
		off := binary.LittleEndian.Uint32(data[stringIDsOff+i*4 : stringIDsOff+i*4+4])
		if int64(off) >= int64(len(data)) {
			continue
		}
		s, ok := readDexString(data[off:])
		if !ok || s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// readDexString decodes one string at the start of b: a uleb128 utf-16 length
// followed by modified UTF-8 that is NUL-terminated.
func readDexString(b []byte) (string, bool) {
	// Skip the uleb128 length; the terminator is authoritative for the bytes.
	i := 0
	for ; i < len(b) && i < 5; i++ {
		if b[i]&0x80 == 0 {
			i++
			break
		}
	}
	if i >= len(b) {
		return "", false
	}
	// The string runs to the first NUL. Bound it so a corrupt table cannot
	// return a slice of the whole file.
	end := bytes.IndexByte(b[i:], 0)
	if end < 0 {
		return "", false
	}
	return string(b[i : i+end]), true
}

// scanDex walks the dex entries, collecting strings for the secret scan and
// deriving the obfuscation signal from class names.
func scanDex(index map[string]*zip.File, info *PackageInfo) []string {
	var all []string
	scanned := 0
	// Per-file string budget. Decompiled packages can hold hundreds of
	// thousands of strings; the credential patterns do not need all of them,
	// and the cap keeps peak memory sane on a large input.
	const perFileStrings = 40000

	for _, name := range info.DexFiles {
		f := index[name]
		if f == nil {
			continue
		}
		data, err := readZipFile(f, maxDexScanBytes)
		if err != nil {
			continue
		}
		stringsFound := dexStrings(data, perFileStrings)
		if len(stringsFound) == 0 {
			continue
		}
		scanned += len(stringsFound)
		all = append(all, stringsFound...)
	}

	info.StringsScanned = scanned
	info.HasObfuscationSignal = looksObfuscated(all)
	return all
}

// looksObfuscated reports whether the identifier population looks minified.
//
// The signal is deliberately conservative: minifiers such as R8 rename most
// application classes to one- and two-character names while leaving framework
// references intact, so the ratio of very short identifiers is a stable
// indicator. A single short name proves nothing, hence a ratio and a floor.
func looksObfuscated(strs []string) bool {
	short, classLike := 0, 0
	for _, s := range strs {
		// Class descriptors look like "Lcom/example/Foo;"
		if len(s) < 3 || s[0] != 'L' || s[len(s)-1] != ';' {
			continue
		}
		classLike++
		body := s[1 : len(s)-1]
		if i := strings.LastIndexByte(body, '/'); i >= 0 {
			body = body[i+1:]
		}
		body = strings.TrimPrefix(body, "$")
		if len(body) <= 2 {
			short++
		}
	}
	// Fewer than 100 classes is too small a sample to judge.
	if classLike < 100 {
		return false
	}
	return float64(short)/float64(classLike) > 0.5
}

// ReadStringsFromZip returns up to limit printable strings from any file in the
// archive whose name ends with one of the given suffixes. It backs the scan of
// native libraries, where credentials are often concatenated into rodata.
func ReadStringsFromZip(index map[string]*zip.File, suffixes []string, limit int) []string {
	var out []string
	for name, f := range index {
		lower := strings.ToLower(name)
		match := false
		for _, suf := range suffixes {
			if strings.HasSuffix(lower, suf) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		data, err := readZipFile(f, 4<<20)
		if err != nil {
			continue
		}
		for _, s := range printableStrings(data) {
			out = append(out, s)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// printableStrings extracts runs of printable ASCII of at least minRun bytes,
// which is how strings appear in a compiled binary.
func printableStrings(data []byte) []string {
	const minRun = 6
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), len(data)+1)
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		start := -1
		for i, b := range data {
			printable := b >= 0x20 && b < 0x7f
			if printable && start < 0 {
				start = i
			}
			if !printable && start >= 0 {
				if i-start >= minRun {
					return i, data[start:i], nil
				}
				start = -1
			}
		}
		if atEOF && start >= 0 && len(data)-start >= minRun {
			return len(data), data[start:], nil
		}
		return len(data), nil, nil
	})
	for sc.Scan() {
		if tok := sc.Text(); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// SecretScanTarget bundles the text collected from a package for scanning.
type SecretScanTarget struct {
	Origin string
	Text   string
}

// CollectSecretTargets gathers the text worth scanning and records where it came
// from. Grouping by origin keeps a finding's Location meaningful.
func CollectSecretTargets(index map[string]*zip.File, info *PackageInfo) []SecretScanTarget {
	var targets []SecretScanTarget

	if dex := scanDex(index, info); len(dex) > 0 {
		targets = append(targets, SecretScanTarget{
			Origin: "classes.dex",
			Text:   strings.Join(dex, "\n"),
		})
	}

	// Native libraries and the resource table are where build-time constants
	// and embedded config end up.
	for name := range index {
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".so") && lower != "resources.arsc" {
			continue
		}
		f := index[name]
		data, err := readZipFile(f, 8<<20)
		if err != nil {
			continue
		}
		if strs := printableStrings(data); len(strs) > 0 {
			targets = append(targets, SecretScanTarget{
				Origin: name,
				Text:   strings.Join(strs, "\n"),
			})
		}
	}
	return targets
}

// AnalyseWithSecrets runs the structural analysis and the credential scan, and
// returns one combined finding set. The structural findings come first, which
// keeps the ordered output stable.
func AnalyseWithSecrets(apkPath string) (*PackageInfo, []Finding, error) {
	info, err := Analyse(apkPath)
	if err != nil {
		return nil, nil, err
	}

	// Re-open for the archive index the scan needs. Analyse already closed its
	// handle, and holding one open across the whole call would keep a lock on
	// a file the operator may be replacing.
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return info, Evaluate(info), nil
	}
	defer r.Close()
	index := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		index[f.Name] = f
	}

	findings := Evaluate(info)
	for _, t := range CollectSecretTargets(index, info) {
		findings = append(findings, ScanSecrets(t.Text, t.Origin)...)
	}
	sortFindings(findings)
	return info, findings, nil
}

// Summary renders the one-line description used in tool output and reports.
func (p *PackageInfo) Summary() string {
	if p == nil {
		return ""
	}
	schemes := "none"
	if p.SigningV1 || p.SigningV2 || p.SigningV3 {
		var parts []string
		if p.SigningV1 {
			parts = append(parts, "v1")
		}
		if p.SigningV2 {
			parts = append(parts, "v2")
		}
		if p.SigningV3 {
			parts = append(parts, "v3")
		}
		schemes = strings.Join(parts, "+")
	}
	return fmt.Sprintf("%s %s (versionCode %s, targetSdk %s, signed %s)",
		p.PackageName, p.VersionName, orDash(p.VersionCode), orDash(p.TargetSDK), schemes)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
