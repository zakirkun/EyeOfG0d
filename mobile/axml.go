// Package mobile provides static analysis of Android packages (APK) for the
// autonomous testing flow: the manifest, signing certificate, native libraries
// and embedded secrets are read from the package itself, without a device and
// without decompiling Java.
//
// Android ships AndroidManifest.xml in the binary XML ("AXML") format, not
// text. This file implements just enough of that container to recover the
// element tree with resolved attribute values, which is what the security
// checks need. It is deliberately narrow: it reads the format the Android build
// tools emit and rejects anything structurally inconsistent instead of guessing,
// because a permissive parser on attacker-supplied input is a liability.
package mobile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Chunk types from the Android resource format. Only the XML-document subset is
// handled here.
const (
	chunkNull            = 0x0000
	chunkStringPool      = 0x0001
	chunkResourceMap     = 0x0180
	chunkStartNamespace  = 0x0100
	chunkEndNamespace    = 0x0101
	chunkStartElement    = 0x0102
	chunkEndElement      = 0x0103
	chunkCDAT            = 0x0104
	chunkXMLHeaderType   = 0x0003
	resXMLFirstChunkType = 0x0100
	resXMLLastChunkType  = 0x017f
)

// Res_value data types. A string attribute stores an index into the string
// pool; every other type carries its value inline in the data word.
const (
	valueTypeNull      = 0x00
	valueTypeReference = 0x01
	valueTypeAttribute = 0x02
	valueTypeString    = 0x03
	valueTypeFloat     = 0x04
	valueTypeIntDec    = 0x10
	valueTypeIntHex    = 0x11
	valueTypeIntBool   = 0x12
)

// ErrNotBinaryXML reports input that does not begin with the XML chunk header.
// Callers use this to fall back to a plain-text manifest, which some repackaged
// or hand-built APKs contain.
var ErrNotBinaryXML = errors.New("not a binary XML document")

// AXMLAttribute is one attribute of a manifest element with its value already
// resolved to a string. References to resources that live outside the manifest
// string pool (theme/style indirection) are rendered as their raw "@0x...".
type AXMLAttribute struct {
	Namespace string
	Name      string
	Value     string
	// Type is the underlying Res_value data type, so callers can tell a real
	// boolean true from the string "true".
	Type uint8
}

// AXMLElement is one element of the parsed tree. Attributes preserve document
// order, and Children preserves the original nesting.
type AXMLElement struct {
	Namespace  string
	Name       string
	Attributes []AXMLAttribute
	Children   []*AXMLElement
	Parent     *AXMLElement
}

// Attr returns the value of the attribute with the given local name, ignoring
// its namespace, and whether it was present.
func (e *AXMLElement) Attr(name string) (string, bool) {
	for _, a := range e.Attributes {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

// AttrDefault returns the attribute value or a fallback when absent.
func (e *AXMLElement) AttrDefault(name, fallback string) string {
	if v, ok := e.Attr(name); ok {
		return v
	}
	return fallback
}

// AttrBool interprets an attribute as an Android boolean. Android accepts the
// literal strings "true" and "false", so both the typed boolean and the string
// encoding must be understood.
func (e *AXMLElement) AttrBool(name string, fallback bool) bool {
	for _, a := range e.Attributes {
		if a.Name != name {
			continue
		}
		if a.Type == valueTypeIntBool {
			return a.Value == "true" || a.Value == "1"
		}
		switch strings.ToLower(strings.TrimSpace(a.Value)) {
		case "true", "1":
			return true
		case "false", "0":
			return false
		}
		return fallback
	}
	return fallback
}

// FindFirst returns the first descendant (or self) whose local name matches.
func (e *AXMLElement) FindFirst(name string) *AXMLElement {
	if e == nil {
		return nil
	}
	if e.Name == name {
		return e
	}
	for _, c := range e.Children {
		if got := c.FindFirst(name); got != nil {
			return got
		}
	}
	return nil
}

// FindAll returns every descendant (or self) whose local name matches, in
// document order.
func (e *AXMLElement) FindAll(name string) []*AXMLElement {
	var out []*AXMLElement
	var walk func(*AXMLElement)
	walk = func(n *AXMLElement) {
		if n.Name == name {
			out = append(out, n)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(e)
	return out
}

// maxAXMLDepth bounds recursion. The format permits arbitrary nesting and the
// document is attacker-controlled, so an unbounded walk could overflow the
// stack on a hand-crafted package.
const maxAXMLDepth = 256

// stringPool decodes the string pool chunk that every AXML document carries.
type stringPool struct {
	strings []string
	utf8    bool
}

func (p *stringPool) at(i uint32) string {
	if int(i) >= len(p.strings) {
		return ""
	}
	return p.strings[i]
}

// parseStringPool decodes a ResStringPool chunk body that starts at offset 0 of
// data and is size bytes long.
func parseStringPool(data []byte, size int) (*stringPool, error) {
	if size < 28 {
		return nil, fmt.Errorf("string pool header too small: %d", size)
	}
	count := binary.LittleEndian.Uint32(data[8:12])
	flags := binary.LittleEndian.Uint32(data[16:20])
	stringsStart := binary.LittleEndian.Uint32(data[20:24])

	pool := &stringPool{utf8: flags&(1<<8) != 0}

	// The offset table is count uint32s immediately after the 28-byte header.
	tableEnd := 28 + int(count)*4
	if count > 0 && tableEnd > size {
		return nil, fmt.Errorf("string pool offset table overruns chunk: count=%d size=%d", count, size)
	}
	if stringsStart > uint32(size) {
		return nil, fmt.Errorf("string pool data start %d beyond chunk size %d", stringsStart, size)
	}
	pool.strings = make([]string, 0, count)
	for i := 0; i < int(count); i++ {
		off := binary.LittleEndian.Uint32(data[28+i*4 : 32+i*4])
		start := int(stringsStart) + int(off)
		if start < 0 || start >= size {
			// A bad offset is not fatal: the pool is still usable for the
			// entries that decode, and the missing string reads as "".
			pool.strings = append(pool.strings, "")
			continue
		}
		s, err := pool.decodeAt(data[start:size])
		if err != nil {
			pool.strings = append(pool.strings, "")
			continue
		}
		pool.strings = append(pool.strings, s)
	}
	return pool, nil
}

// decodeAt reads one length-prefixed string. UTF-8 pools use a 1- or 2-byte
// character count then a 1- or 2-byte byte count; UTF-16 pools use a 1- or
// 2-byte UTF-16 unit count.
func (p *stringPool) decodeAt(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errors.New("empty string")
	}
	if p.utf8 {
		// Skip the UTF-16 length, then read the UTF-8 byte length.
		_, n := decodeLen8(b)
		if n > len(b) {
			return "", errors.New("truncated utf8 length")
		}
		byteLen, n2 := decodeLen8(b[n:])
		n += n2
		if n+byteLen > len(b) || byteLen < 0 {
			return "", errors.New("utf8 string overruns pool")
		}
		return string(b[n : n+byteLen]), nil
	}
	unitLen, n := decodeLen16(b)
	if n > len(b) {
		return "", errors.New("truncated utf16 length")
	}
	if unitLen < 0 || n+unitLen*2 > len(b) {
		return "", errors.New("utf16 string overruns pool")
	}
	units := make([]uint16, unitLen)
	for i := 0; i < unitLen; i++ {
		units[i] = binary.LittleEndian.Uint16(b[n+i*2 : n+i*2+2])
	}
	return string(utf16.Decode(units)), nil
}

// decodeLen8 reads the variable-length prefix used by UTF-8 pools: a high bit
// set on the first byte means a second byte follows.
func decodeLen8(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1
	}
	if len(b) < 2 {
		return 0, 1
	}
	return (int(b[0]&0x7f) << 8) | int(b[1]), 2
}

// decodeLen16 reads the same prefix from UTF-16 unit counts, where both bytes
// are 16-bit halves of the length.
func decodeLen16(b []byte) (int, int) {
	if len(b) < 2 {
		return 0, 0
	}
	first := binary.LittleEndian.Uint16(b[:2])
	if first&0x8000 == 0 {
		return int(first), 2
	}
	if len(b) < 4 {
		return 0, 2
	}
	second := binary.LittleEndian.Uint16(b[2:4])
	return (int(first&0x7fff) << 16) | int(second), 4
}

// ParseAXML parses a binary AndroidManifest.xml and returns the root element.
func ParseAXML(data []byte) (*AXMLElement, error) {
	if len(data) < 8 {
		return nil, ErrNotBinaryXML
	}
	if binary.LittleEndian.Uint16(data[0:2]) != chunkXMLHeaderType {
		return nil, ErrNotBinaryXML
	}
	headerSize := int(binary.LittleEndian.Uint16(data[2:4]))
	if headerSize < 8 || headerSize > len(data) {
		return nil, fmt.Errorf("xml header size %d out of range", headerSize)
	}

	var (
		pool *stringPool
		root *AXMLElement
		cur  *AXMLElement
		// stack tracks open elements so EndElement chunks close the right one.
		stack []*AXMLElement
	)

	off := headerSize
	for off+8 <= len(data) {
		typ := binary.LittleEndian.Uint16(data[off : off+2])
		chunkHeaderSize := int(binary.LittleEndian.Uint16(data[off+2 : off+4]))
		size := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))
		if size < 8 || off+size > len(data) {
			return nil, fmt.Errorf("chunk type 0x%04x size %d overruns document at %d", typ, size, off)
		}
		body := data[off : off+size]

		switch typ {
		case chunkStringPool:
			p, err := parseStringPool(body, size)
			if err != nil {
				return nil, err
			}
			pool = p

		case chunkStartElement:
			if pool == nil {
				return nil, errors.New("start element before string pool")
			}
			if len(stack) >= maxAXMLDepth {
				return nil, fmt.Errorf("element nesting exceeds %d", maxAXMLDepth)
			}
			el, err := parseStartElement(body, chunkHeaderSize, pool)
			if err != nil {
				return nil, err
			}
			if cur != nil {
				el.Parent = cur
				cur.Children = append(cur.Children, el)
			} else if root == nil {
				root = el
			}
			stack = append(stack, el)
			cur = el

		case chunkEndElement:
			if n := len(stack); n > 0 {
				stack = stack[:n-1]
				if n-1 == 0 {
					cur = nil
				} else {
					cur = stack[n-2]
				}
			}

		case chunkResourceMap, chunkStartNamespace, chunkEndNamespace, chunkCDAT, chunkNull:
			// Metadata: no effect on the element tree the checks consume.

		default:
			// Unknown XML chunk types are skipped rather than rejected: new
			// toolchains add chunk types, and the ones above cover every
			// element-bearing kind.
			if typ < resXMLFirstChunkType || typ > resXMLLastChunkType {
				// Not an XML chunk at all - stop instead of walking off into
				// unrelated trailing data.
				off = len(data)
				continue
			}
		}
		off += size
	}

	if root == nil {
		return nil, errors.New("binary XML contained no root element")
	}
	return root, nil
}

// parseStartElement decodes one ResXMLTree start-element chunk.
func parseStartElement(body []byte, headerSize int, pool *stringPool) (*AXMLElement, error) {
	// ResXMLTree_node is 16 bytes: chunk header (8) + lineNumber (4) + comment (4).
	if len(body) < 16 {
		return nil, errors.New("start element node truncated")
	}
	// The extended struct begins after the node header.
	const nodeSize = 16
	if len(body) < nodeSize+20 {
		return nil, errors.New("start element extension truncated")
	}
	ext := body[nodeSize:]
	nameIdx := binary.LittleEndian.Uint32(ext[4:8])
	attrStart := int(binary.LittleEndian.Uint16(ext[8:10]))
	attrSize := int(binary.LittleEndian.Uint16(ext[10:12]))
	attrCount := int(binary.LittleEndian.Uint16(ext[12:14]))

	el := &AXMLElement{Name: pool.at(nameIdx)}
	nsIdx := binary.LittleEndian.Uint32(ext[0:4])
	el.Namespace = pool.at(nsIdx)

	if attrCount == 0 {
		return el, nil
	}
	// Attributes begin at node header + headerSize (the chunk header size the
	// encoder reported), offset by attrStart. Some encoders set attrStart to 20
	// relative to the extension; using the declared value keeps both correct.
	base := headerSize + attrStart
	if base < nodeSize+20 {
		base = nodeSize + attrStart
	}
	if attrSize < 20 {
		attrSize = 20
	}
	if base < 0 || base+attrCount*attrSize > len(body) {
		return nil, fmt.Errorf("attribute table overruns chunk: base=%d count=%d size=%d body=%d",
			base, attrCount, attrSize, len(body))
	}
	for i := 0; i < attrCount; i++ {
		a := body[base+i*attrSize : base+(i+1)*attrSize]
		attrNS := pool.at(binary.LittleEndian.Uint32(a[0:4]))
		attrName := pool.at(binary.LittleEndian.Uint32(a[4:8]))
		rawIdx := binary.LittleEndian.Uint32(a[8:12])
		// Res_value: size (2) + res0 (1) + dataType (1) + data (4)
		dataType := a[15]
		data := binary.LittleEndian.Uint32(a[16:20])

		attr := AXMLAttribute{
			Namespace: attrNS,
			Name:      attrName,
			Type:      dataType,
		}
		switch dataType {
		case valueTypeString:
			attr.Value = pool.at(data)
			if attr.Value == "" && rawIdx != 0xffffffff {
				attr.Value = pool.at(rawIdx)
			}
		case valueTypeIntBool:
			if data != 0 {
				attr.Value = "true"
			} else {
				attr.Value = "false"
			}
		case valueTypeIntDec:
			attr.Value = fmt.Sprintf("%d", int32(data))
		case valueTypeIntHex:
			attr.Value = fmt.Sprintf("0x%x", data)
		case valueTypeReference, valueTypeAttribute:
			// A resource reference cannot be resolved without resources.arsc;
			// surface the id so a reviewer can see it was not silently dropped.
			attr.Value = fmt.Sprintf("@0x%08x", data)
		case valueTypeNull:
			attr.Value = ""
		default:
			// Floats, dimensions and colours are not meaningful for these
			// checks; keep the numeric form rather than an empty string.
			attr.Value = fmt.Sprintf("%d", data)
		}
		el.Attributes = append(el.Attributes, attr)
	}
	return el, nil
}
