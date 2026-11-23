package mobile

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// ParsePlainXML parses a textual AndroidManifest.xml into the same element tree
// ParseAXML produces.
//
// Repackaged APKs and hand-built test packages sometimes carry a plain-text
// manifest. Accepting both forms means the analyser never has to guess which
// kind it was handed, and the rest of the pipeline stays single-shaped.
func ParsePlainXML(data []byte) (*AXMLElement, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Android manifests are UTF-8 without a DTD; the strict decoder is right
	// here, and refusing entity declarations avoids expansion attacks.
	dec.Strict = true

	var (
		root  *AXMLElement
		stack []*AXMLElement
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxAXMLDepth {
				return nil, fmt.Errorf("element nesting exceeds %d", maxAXMLDepth)
			}
			el := &AXMLElement{
				Namespace: t.Name.Space,
				Name:      t.Name.Local,
			}
			for _, a := range t.Attr {
				// The android namespace is bound to different URIs depending
				// on the document; the local name is what the checks key on.
				name := a.Name.Local
				if strings.EqualFold(name, "xmlns") || strings.HasPrefix(a.Name.Local, "xmlns") {
					continue
				}
				el.Attributes = append(el.Attributes, AXMLAttribute{
					// Android attributes use the literal prefix "android"; keep
					// it so a reviewer sees which namespace a value came from.
					Namespace: androidAttrNamespace(a.Name.Space),
					Name:      name,
					Value:     a.Value,
					Type:      valueTypeString,
				})
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				el.Parent = parent
				parent.Children = append(parent.Children, el)
			} else if root == nil {
				root = el
			}
			stack = append(stack, el)

		case xml.EndElement:
			if n := len(stack); n > 0 {
				stack = stack[:n-1]
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("xml contained no root element")
	}
	return root, nil
}

// androidAttrNamespace normalises the namespace URI of a plain-XML attribute to
// the short form the binary parser produces, so consumers see one spelling.
func androidAttrNamespace(space string) string {
	if space == "" {
		return ""
	}
	if strings.Contains(space, "android.com/apk/res/android") {
		return "android"
	}
	return space
}
