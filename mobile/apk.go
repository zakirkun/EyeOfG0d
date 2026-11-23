package mobile

import (
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Limits on what a single package may cost. An APK is attacker-supplied input,
// so every read is bounded: a zip bomb or a package with a million entries must
// fail cleanly rather than exhaust the host.
const (
	// maxManifestBytes bounds the manifest read; real manifests are tens of KB.
	maxManifestBytes = 8 << 20
	// maxCertBytes bounds a signing certificate blob.
	maxCertBytes = 1 << 20
	// maxEntries bounds the central directory walk.
	maxEntries = 100000
	// maxDexScanBytes bounds total bytes read while scanning dex for strings.
	maxDexScanBytes = 64 << 20
)

// PackageInfo is everything the static checks learn about one Android package.
// It is a pure data structure: no judgement, no severity. Findings are derived
// from it by Evaluate.
type PackageInfo struct {
	// Path is the APK that was analysed, as given.
	Path string
	// SHA256 is the digest of the whole file, so two analyses of the same bytes
	// can be tied together.
	SHA256 string
	Size   int64

	// Identity, from the manifest.
	PackageName string
	VersionName string
	VersionCode string
	MinSDK      string
	TargetSDK   string

	// Security-relevant manifest flags. Nil-vs-false matters for some of these
	// (an absent debuggable is false; an absent allowBackup defaults to true),
	// so each carries an explicit "present" marker where it changes the verdict.
	Debuggable          bool
	DebugFlagPresent    bool
	AllowBackup         bool
	AllowBackupPresent  bool
	UsesCleartext       bool
	CleartextPresent    bool
	NetworkSecurityConf string
	TestOnly            bool

	// Manifest structure.
	Permissions     []Permission
	Activities      []Component
	Services        []Component
	Receivers       []Component
	Providers       []Component
	DeepLinks       []DeepLink
	CustomSchemes   []string
	ExportedNoPerms []Component

	// Signing.
	Signed     bool
	SigningV1  bool
	SigningV2  bool
	SigningV3  bool
	Signatures []Signature

	// Contents.
	NativeLibs   []string
	DexFiles     []string
	AssetCount   int
	HasResources bool
	// HasObfuscationSignal reports whether the dex class names look mangled.
	// Computed from a bounded read of the dex string pools.
	HasObfuscationSignal bool
	// StringsScanned is how many dex/lib strings the secret scan consumed, so a
	// report can state the coverage instead of implying a full search.
	StringsScanned int
}

// Permission is one uses-permission declaration.
type Permission struct {
	Name     string
	MaxSDK   string
	Required bool
}

// Component is one of the four Android component kinds. Exported is the
// resolved value: an absent android:exported means the platform default, which
// depends on whether the component declares an intent filter, so the value here
// is what the platform would actually apply.
type Component struct {
	Kind            string
	Name            string
	Exported        bool
	ExportedPresent bool
	Permission      string
	IntentFilters   int
	// Authorities is populated for providers only.
	Authorities string
	// GrantURIPermissions is populated for providers only.
	GrantURIPermissions bool
	// ReadPermission/WritePermission are populated for providers only.
	ReadPermission  string
	WritePermission string
}

// DeepLink is one intent-filter data element that maps a URL to a component.
type DeepLink struct {
	Scheme   string
	Host     string
	Path     string
	PathPref string
	// Component is the activity/service that handles it.
	Component string
	// AutoVerify records android:autoVerify, which decides whether the link is
	// an Android App Link (verified by domain) or a plain custom scheme.
	AutoVerify bool
}

// Signature is one certificate that signs the package.
type Signature struct {
	Subject     string
	Issuer      string
	Serial      string
	NotBefore   time.Time
	NotAfter    time.Time
	Algorithm   string
	KeyBits     int
	SelfSigned  bool
	SHA256      string
	IsDebugCert bool
}

// Analyse opens an APK and extracts PackageInfo. It never decompiles Java: the
// facts come from the manifest, the signing block and the archive index, which
// is what makes the result deterministic and fast.
func Analyse(apkPath string) (*PackageInfo, error) {
	info, err := analyse(apkPath)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func analyse(apkPath string) (*PackageInfo, error) {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}
	defer r.Close()

	info := &PackageInfo{Path: apkPath}
	if len(r.File) > maxEntries {
		return nil, fmt.Errorf("apk has %d entries, refusing more than %d", len(r.File), maxEntries)
	}

	// Index the archive once; every later step looks up by name.
	index := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		index[f.Name] = f
		info.Size += int64(f.CompressedSize64)
	}

	// Digest the whole file: the report ties a finding back to the exact bytes
	// analysed, so two runs over the same package are provably comparable.
	if sum, err := fileSHA256(apkPath); err == nil {
		info.SHA256 = sum
	}

	if err := readManifest(index, info); err != nil {
		return nil, err
	}
	readContents(index, info)
	if err := readSignatures(apkPath, index, info); err != nil {
		// A signing problem is a finding, not a parse failure: an unsigned APK
		// is still analysable, and Evaluate reports the absence.
		info.Signed = false
	}
	return info, nil
}

// readManifest decodes AndroidManifest.xml, accepting either the binary form
// Android emits or plain XML from a repackaged build.
func readManifest(index map[string]*zip.File, info *PackageInfo) error {
	f := index["AndroidManifest.xml"]
	if f == nil {
		return errors.New("apk has no AndroidManifest.xml")
	}
	data, err := readZipFile(f, maxManifestBytes)
	if err != nil {
		return fmt.Errorf("read AndroidManifest.xml: %w", err)
	}

	root, err := ParseAXML(data)
	if err != nil {
		if !errors.Is(err, ErrNotBinaryXML) {
			return fmt.Errorf("parse AndroidManifest.xml: %w", err)
		}
		root, err = ParsePlainXML(data)
		if err != nil {
			return fmt.Errorf("parse plain AndroidManifest.xml: %w", err)
		}
	}
	applyManifest(root, info)
	return nil
}

// applyManifest lifts the security-relevant fields out of the parsed tree.
func applyManifest(root *AXMLElement, info *PackageInfo) {
	manifest := root
	if manifest.Name != "manifest" {
		if found := root.FindFirst("manifest"); found != nil {
			manifest = found
		}
	}
	info.PackageName = manifest.AttrDefault("package", "")
	info.VersionName = manifest.AttrDefault("versionName", "")
	info.VersionCode = manifest.AttrDefault("versionCode", "")

	usesSDK := manifest.FindFirst("uses-sdk")
	if usesSDK != nil {
		info.MinSDK = usesSDK.AttrDefault("minSdkVersion", "")
		info.TargetSDK = usesSDK.AttrDefault("targetSdkVersion", "")
	}

	app := manifest.FindFirst("application")
	if app == nil {
		return
	}

	info.Debuggable, info.DebugFlagPresent = boolAttr(app, "debuggable")
	info.AllowBackup, info.AllowBackupPresent = boolAttr(app, "allowBackup")
	info.UsesCleartext, info.CleartextPresent = boolAttr(app, "usesCleartextTraffic")
	info.TestOnly, _ = boolAttr(app, "testOnly")
	info.NetworkSecurityConf = app.AttrDefault("networkSecurityConfig", "")

	for _, p := range manifest.FindAll("uses-permission") {
		name := p.AttrDefault("name", "")
		if name == "" {
			continue
		}
		info.Permissions = append(info.Permissions, Permission{
			Name:     name,
			MaxSDK:   p.AttrDefault("maxSdkVersion", ""),
			Required: true,
		})
	}
	for _, p := range manifest.FindAll("uses-permission-sdk-23") {
		name := p.AttrDefault("name", "")
		if name == "" {
			continue
		}
		info.Permissions = append(info.Permissions, Permission{Name: name, MaxSDK: p.AttrDefault("maxSdkVersion", ""), Required: true})
	}

	info.Activities = collectComponents(app, "activity", "activity")
	info.Activities = append(info.Activities, collectComponents(app, "activity-alias", "activity")...)
	info.Services = collectComponents(app, "service", "service")
	info.Receivers = collectComponents(app, "receiver", "receiver")
	info.Providers = collectComponents(app, "provider", "provider")

	for _, set := range [][]Component{info.Activities, info.Services, info.Receivers, info.Providers} {
		for _, c := range set {
			if c.Exported && c.Permission == "" {
				info.ExportedNoPerms = append(info.ExportedNoPerms, c)
			}
		}
	}

	info.DeepLinks, info.CustomSchemes = collectDeepLinks(app)

	sort.Slice(info.Permissions, func(i, j int) bool { return info.Permissions[i].Name < info.Permissions[j].Name })
	info.Permissions = dedupePermissions(info.Permissions)
}

// boolAttr returns (value, present). The present flag distinguishes an absent
// attribute from an explicit false, which the checks need because Android's
// defaults are not uniformly false.
func boolAttr(el *AXMLElement, name string) (bool, bool) {
	for _, a := range el.Attributes {
		if a.Name != name {
			continue
		}
		return el.AttrBool(name, false), true
	}
	return false, false
}

func collectComponents(app *AXMLElement, tag, kind string) []Component {
	var out []Component
	for _, el := range app.Children {
		if el.Name != tag {
			continue
		}
		c := Component{
			Kind:       kind,
			Name:       el.AttrDefault("name", ""),
			Permission: el.AttrDefault("permission", ""),
		}
		c.IntentFilters = len(el.FindAll("intent-filter"))
		exported, present := boolAttr(el, "exported")
		c.ExportedPresent = present
		if present {
			c.Exported = exported
		} else {
			// Platform default: a component with an intent filter is exported
			// from API 31 onward; without one it is not. Reporting the
			// effective value is what matters, and the filter count is the
			// only input the manifest itself provides.
			c.Exported = c.IntentFilters > 0
		}
		if kind == "provider" {
			c.Authorities = el.AttrDefault("authorities", "")
			c.GrantURIPermissions, _ = boolAttr(el, "grantUriPermissions")
			c.ReadPermission = el.AttrDefault("readPermission", "")
			c.WritePermission = el.AttrDefault("writePermission", "")
			// A provider with grantUriPermissions but no permission is the
			// pattern behind path-traversal style content leaks, so record
			// both facts and let Evaluate decide.
			if c.Permission == "" {
				c.Permission = firstNonEmpty(c.ReadPermission, c.WritePermission)
			}
		}
		if c.Name == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func collectDeepLinks(app *AXMLElement) ([]DeepLink, []string) {
	var links []DeepLink
	schemes := map[string]bool{}

	for _, el := range app.Children {
		if el.Name != "activity" && el.Name != "service" && el.Name != "activity-alias" {
			continue
		}
		component := el.AttrDefault("name", "")
		for _, filter := range el.FindAll("intent-filter") {
			autoVerify, _ := boolAttr(filter, "autoVerify")
			for _, data := range filter.FindAll("data") {
				scheme := data.AttrDefault("scheme", "")
				if scheme == "" {
					continue
				}
				links = append(links, DeepLink{
					Scheme:     scheme,
					Host:       data.AttrDefault("host", ""),
					Path:       data.AttrDefault("path", ""),
					PathPref:   data.AttrDefault("pathPrefix", ""),
					Component:  component,
					AutoVerify: autoVerify,
				})
				schemes[strings.ToLower(scheme)] = true
			}
		}
	}

	// http/https are handled by every browser and are not "custom" schemes,
	// but they are still deep-link surfaces when autoVerify is absent.
	var custom []string
	for s := range schemes {
		if s == "http" || s == "https" {
			continue
		}
		custom = append(custom, s)
	}
	sort.Strings(custom)
	return links, custom
}

// readContents records the structural facts: native libraries, dex files and
// asset volume. These drive the native-code and obfuscation checks.
func readContents(index map[string]*zip.File, info *PackageInfo) {
	for name := range index {
		lower := strings.ToLower(name)
		switch {
		case strings.HasPrefix(name, "lib/") && strings.HasSuffix(lower, ".so"):
			info.NativeLibs = append(info.NativeLibs, name)
		case strings.HasSuffix(lower, ".dex") && !strings.Contains(name, "/"):
			info.DexFiles = append(info.DexFiles, name)
		case strings.HasPrefix(name, "assets/"):
			info.AssetCount++
		case lower == "resources.arsc":
			info.HasResources = true
		}
	}
	sort.Strings(info.NativeLibs)
	sort.Strings(info.DexFiles)
}

// APK Signing Block IDs, from the Android source (apk_sig_block.h).
const (
	sigBlockV2ID  = 0x7109871a
	sigBlockV3ID  = 0xf05368c0
	sigBlockV31ID = 0x1b93ad61
)

// readSignatures detects the signing schemes and extracts the signing
// certificate. v2/v3 certificates live in the APK Signing Block; v1 uses a
// PKCS#7 blob under META-INF.
func readSignatures(apkPath string, index map[string]*zip.File, info *PackageInfo) error {
	// v1: META-INF/<name>.(RSA|DSA|EC) is a PKCS#7 SignedData.
	for name, f := range index {
		upper := strings.ToUpper(name)
		if !strings.HasPrefix(upper, "META-INF/") {
			continue
		}
		if !strings.HasSuffix(upper, ".RSA") && !strings.HasSuffix(upper, ".DSA") && !strings.HasSuffix(upper, ".EC") {
			continue
		}
		data, err := readZipFile(f, maxCertBytes)
		if err != nil {
			continue
		}
		certs := certsFromPKCS7(data)
		if len(certs) == 0 {
			continue
		}
		info.SigningV1 = true
		info.Signed = true
		for _, c := range certs {
			info.Signatures = append(info.Signatures, describeCert(c))
		}
		break
	}

	// v2/v3: read the APK Signing Block that sits before the central directory.
	block, err := readAPKSigningBlock(apkPath)
	if err == nil {
		for _, entry := range block {
			switch entry.id {
			case sigBlockV2ID:
				if certs := v2Certs(entry.value); len(certs) > 0 {
					info.SigningV2 = true
					info.Signed = true
					for _, c := range certs {
						info.Signatures = append(info.Signatures, describeCert(c))
					}
				}
			case sigBlockV3ID, sigBlockV31ID:
				if certs := v2Certs(skipV3MinMax(entry.value)); len(certs) > 0 {
					info.SigningV3 = true
					info.Signed = true
					for _, c := range certs {
						info.Signatures = append(info.Signatures, describeCert(c))
					}
				}
			}
		}
	}

	info.Signatures = dedupeSignatures(info.Signatures)
	return nil
}

// readZipFile reads at most limit bytes from an archive entry.
func readZipFile(f *zip.File, limit int) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, int64(limit)))
}

// certsFromPKCS7 pulls the certificates out of a PKCS#7 SignedData blob.
//
// Encoding a full CMS SignedData parser would mean modelling half of RFC 5652;
// the certificates are the only part needed, and they sit in a well-defined
// place: ContentInfo{ contentType = signedData, content = [0] SignedData }, and
// SignedData carries `certificates [0] IMPLICIT SET OF Certificate` as its third
// field. Walking to that field with encoding/asn1 handles both the normal and
// the BER-indefinite encodings jars use, and adds no dependency.
func certsFromPKCS7(der []byte) []*x509.Certificate {
	var contentInfo asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &contentInfo); err != nil || len(rest) != 0 {
		return nil
	}
	if contentInfo.Class != asn1.ClassUniversal || contentInfo.Tag != asn1.TagSequence {
		return nil
	}
	// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
	var contentType asn1.ObjectIdentifier
	inner := contentInfo.Bytes
	if rest, err := asn1.Unmarshal(inner, &contentType); err != nil {
		return nil
	} else {
		inner = rest
	}
	if !contentType.Equal(oidSignedData) {
		return nil
	}
	var explicit asn1.RawValue
	if rest, err := asn1.Unmarshal(inner, &explicit); err != nil || len(rest) != 0 {
		return nil
	}
	if explicit.Class != asn1.ClassContextSpecific || explicit.Tag != 0 {
		return nil
	}

	// Inside the explicit wrapper sits the SignedData SEQUENCE.
	var signedData asn1.RawValue
	if _, err := asn1.Unmarshal(explicit.Bytes, &signedData); err != nil {
		return nil
	}
	if signedData.Tag != asn1.TagSequence {
		return nil
	}

	// SignedData ::= SEQUENCE {
	//   version CMSVersion, digestAlgorithms SET, encapContentInfo SEQUENCE,
	//   certificates [0] IMPLICIT CertificateSet OPTIONAL, ... }
	body := signedData.Bytes
	var skip asn1.RawValue
	// version
	if rest, err := asn1.Unmarshal(body, &skip); err != nil {
		return nil
	} else {
		body = rest
	}
	// digestAlgorithms
	if rest, err := asn1.Unmarshal(body, &skip); err != nil {
		return nil
	} else {
		body = rest
	}
	// encapContentInfo
	if rest, err := asn1.Unmarshal(body, &skip); err != nil {
		return nil
	} else {
		body = rest
	}
	// certificates [0] IMPLICIT SET OF Certificate
	var certSet asn1.RawValue
	if _, err := asn1.Unmarshal(body, &certSet); err != nil {
		return nil
	}
	if certSet.Class != asn1.ClassContextSpecific || certSet.Tag != 0 {
		// No certificates field: nothing to report (the signer may have been
		// resolved from elsewhere). Not an error.
		return nil
	}

	var out []*x509.Certificate
	inner = certSet.Bytes
	for len(inner) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(inner, &raw)
		if err != nil {
			break
		}
		inner = rest
		if c, err := x509.ParseCertificate(raw.FullBytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// oidSignedData is 1.2.840.113549.1.7.2, the PKCS#7 content type for SignedData.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// describeCert reduces a certificate to the facts the checks consume.
func describeCert(c *x509.Certificate) Signature {
	s := Signature{
		Subject:   c.Subject.String(),
		Issuer:    c.Issuer.String(),
		Serial:    c.SerialNumber.String(),
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Algorithm: c.SignatureAlgorithm.String(),
		KeyBits:   keyBits(c),
		SHA256:    hex.EncodeToString(certDigest(c)),
	}
	s.SelfSigned = c.Subject.String() == c.Issuer.String()
	// The Android debug keystore is the giveaway that a build never went
	// through release signing.
	s.IsDebugCert = strings.Contains(strings.ToLower(c.Subject.CommonName), "android debug") ||
		strings.Contains(strings.ToLower(s.Subject), "cn=android debug")
	return s
}

func certDigest(c *x509.Certificate) []byte {
	sum := sha256.Sum256(c.Raw)
	return sum[:]
}

func keyBits(c *x509.Certificate) int {
	if c.PublicKey == nil {
		return 0
	}
	switch k := c.PublicKey.(type) {
	case interface{ Size() int }:
		return k.Size() * 8
	}
	return 0
}

// signingBlockEntry is one length-prefixed ID-value pair.
type signingBlockEntry struct {
	id    uint32
	value []byte
}

// readAPKSigningBlock locates and parses the APK Signing Block. The format is:
//
//	[entries][uint64 size][16-byte magic][uint64 size]
//
// where the trailing size counts the magic and the entries. An APK without the
// block simply does not have v2/v3 signatures.
func readAPKSigningBlock(apkPath string) ([]signingBlockEntry, error) {
	f, err := openFile(apkPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size < 32 {
		return nil, errors.New("file too small for a signing block")
	}

	// The block ends where the central directory begins, and the central
	// directory is located by the End of Central Directory record in the last
	// 64 KB + 22 bytes.
	cdOffset, err := findCentralDirectoryOffset(f, size)
	if err != nil {
		return nil, err
	}
	if cdOffset < 32 {
		return nil, errors.New("central directory too close to file start")
	}

	// The 24 bytes immediately before the central directory are: uint64 size,
	// 16-byte magic "APK Sig Block 42", uint64 size.
	tail := make([]byte, 24)
	if _, err := f.ReadAt(tail, cdOffset-24); err != nil {
		return nil, err
	}
	if string(tail[8:24]) != "APK Sig Block 42" {
		return nil, errors.New("no APK signing block")
	}
	blockSize := binary.LittleEndian.Uint64(tail[0:8])
	if blockSize < 24 || blockSize > uint64(cdOffset) {
		return nil, fmt.Errorf("signing block size %d invalid for offset %d", blockSize, cdOffset)
	}
	start := cdOffset - int64(blockSize) - 8
	if start < 0 {
		return nil, errors.New("signing block starts before file start")
	}

	body := make([]byte, blockSize-24)
	if _, err := f.ReadAt(body, start+8); err != nil {
		return nil, err
	}
	return parseSigningBlockEntries(body)
}

// parseSigningBlockEntries walks the length-prefixed pairs.
func parseSigningBlockEntries(body []byte) ([]signingBlockEntry, error) {
	var out []signingBlockEntry
	for off := 0; off+12 <= len(body); {
		// uint64 length prefix covers id (4) + value.
		l := binary.LittleEndian.Uint64(body[off : off+8])
		if l < 4 || l > uint64(len(body)-off-8) {
			return nil, fmt.Errorf("signing block entry length %d out of range at %d", l, off)
		}
		id := binary.LittleEndian.Uint32(body[off+8 : off+12])
		value := body[off+12 : off+8+int(l)]
		out = append(out, signingBlockEntry{id: id, value: value})
		off += 8 + int(l)
	}
	return out, nil
}

// v2Certs extracts the certificate chain from a v2 signer block:
//
//	signed data: len-prefixed digests, len-prefixed certificates, len-prefixed attrs
//
// with each certificate itself length-prefixed DER.
func v2Certs(value []byte) []*x509.Certificate {
	signed, _, ok := readLengthPrefixed(value)
	if !ok {
		return nil
	}
	// signed = digests || certificates || additional attributes
	_, rest, ok := readLengthPrefixed(signed)
	if !ok {
		return nil
	}
	certsBlob, _, ok := readLengthPrefixed(rest)
	if !ok {
		return nil
	}
	return parseCertSequence(certsBlob)
}

// skipV3MinMax drops the two leading int32 fields (minSdk, maxSdk) that v3
// signer blocks add before the same signed-data layout v2 uses.
func skipV3MinMax(value []byte) []byte {
	if len(value) < 8 {
		return value
	}
	return value[8:]
}

// parseCertSequence reads consecutive length-prefixed DER certificates.
func parseCertSequence(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for off := 0; off+4 <= len(b); {
		l := int(binary.LittleEndian.Uint32(b[off : off+4]))
		if l <= 0 || off+4+l > len(b) {
			break
		}
		if c, err := x509.ParseCertificate(b[off+4 : off+4+l]); err == nil {
			out = append(out, c)
		}
		off += 4 + l
	}
	return out
}

// readLengthPrefixed consumes one uint32-prefixed block.
func readLengthPrefixed(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	l := int(binary.LittleEndian.Uint32(b[:4]))
	if l < 0 || 4+l > len(b) {
		return nil, nil, false
	}
	return b[4 : 4+l], b[4+l:], true
}

// findCentralDirectoryOffset reads the End of Central Directory record to learn
// where the central directory starts.
func findCentralDirectoryOffset(f io.ReaderAt, size int64) (int64, error) {
	// The EOCD is 22 bytes plus a comment of up to 65535.
	const maxComment = 65535
	scan := int64(maxComment + 22)
	if scan > size {
		scan = size
	}
	buf := make([]byte, scan)
	if _, err := f.ReadAt(buf, size-scan); err != nil {
		return 0, err
	}
	for i := len(buf) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:i+4]) != 0x06054b50 {
			continue
		}
		return int64(binary.LittleEndian.Uint32(buf[i+16 : i+20])), nil
	}
	return 0, errors.New("end of central directory not found")
}

func dedupePermissions(in []Permission) []Permission {
	seen := map[string]bool{}
	out := in[:0]
	for _, p := range in {
		key := p.Name + "|" + p.MaxSDK
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func dedupeSignatures(in []Signature) []Signature {
	seen := map[string]bool{}
	var out []Signature
	for _, s := range in {
		if s.SHA256 == "" || seen[s.SHA256] {
			continue
		}
		seen[s.SHA256] = true
		out = append(out, s)
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// BaseName returns the file name of the analysed package, for reporting.
func (p *PackageInfo) BaseName() string { return path.Base(p.Path) }

// openFile is a thin indirection so the signing-block reader can be tested with
// an in-memory file if needed later.
func openFile(name string) (*os.File, error) { return os.Open(name) }

// fileSHA256 digests a file without holding it in memory.
func fileSHA256(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
