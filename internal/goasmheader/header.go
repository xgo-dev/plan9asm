// Package goasmheader provides pure bounded header syntax. Definitions, JSON
// and digests authenticate no SDK, compiler, package or memory capability.
package goasmheader

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

// ByteLimit preserves the existing full-definition textual contract.
const ByteLimit = 64 << 20

func Definitions(header []byte) (map[string]string, error) {
	if len(header) > ByteLimit {
		return nil, fmt.Errorf("generated header exceeds its bounded textual contract")
	}
	text := string(header)
	if strings.ContainsRune(text, '\x00') {
		return nil, fmt.Errorf("generated header exceeds its bounded textual contract")
	}
	definitions := make(map[string]string)
	canonicalBytes := 0
	for text != "" {
		var line string
		line, text, _ = strings.Cut(text, "\n")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		directive, remainder := generatedHeaderToken(line)
		name, value := generatedHeaderToken(remainder)
		if directive != "#define" || !token.IsIdentifier(name) {
			return nil, fmt.Errorf("unrecognized generated header definition: %s", line)
		}
		if _, exists := definitions[name]; exists {
			return nil, fmt.Errorf("duplicate generated header definition: %s", name)
		}
		size, err := DefinitionSize(name, value)
		if err != nil || size > ByteLimit-canonicalBytes {
			return nil, fmt.Errorf("invalid or unbounded generated header definition: %s", name)
		}
		canonicalBytes += size
		definitions[name] = value
	}
	return definitions, nil
}

func generatedHeaderToken(text string) (string, string) {
	index := strings.IndexFunc(text, unicode.IsSpace)
	if index < 0 {
		return text, ""
	}
	return text[:index], strings.TrimSpace(text[index:])
}

func DefinitionSize(name, value string) (int, error) {
	// Check lengths before scanning values or allocating canonical output. Both
	// component bounds also keep this addition safe on the supported 32-bit Go.
	if len(name) > ByteLimit || len(value) > ByteLimit {
		return 0, fmt.Errorf("unbounded generated header definition")
	}
	size := len("#define ") + len(name) + 1 + len(value) + 1
	if size > ByteLimit {
		return 0, fmt.Errorf("unbounded generated header definition")
	}
	if !token.IsIdentifier(name) || value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\r\n\x00") || strings.HasSuffix(value, "\\") {
		return 0, fmt.Errorf("noncanonical generated header definition")
	}
	return size, nil
}

func DefinitionsSize(definitions map[string]string) (int, error) {
	if definitions == nil {
		return 0, fmt.Errorf("missing generated header definitions")
	}
	total := 0
	for name, value := range definitions {
		size, err := DefinitionSize(name, value)
		if err != nil {
			return 0, err
		}
		if size > ByteLimit-total {
			return 0, fmt.Errorf("generated header exceeds its canonical byte bound")
		}
		total += size
	}
	return total, nil
}

func SHA256(definitions map[string]string) string {
	if len(definitions) == 0 {
		definitions = map[string]string{}
	}
	data, _ := json.Marshal(definitions)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func Canonical(definitions map[string]string) ([]byte, error) {
	size, err := DefinitionsSize(definitions)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(definitions))
	for name := range definitions {
		names = append(names, name)
	}
	sort.Strings(names)
	var text strings.Builder
	text.Grow(size)
	for _, name := range names {
		fmt.Fprintf(&text, "#define %s %s\n", name, definitions[name])
	}
	data := []byte(text.String())
	parsed, err := Definitions(data)
	if err != nil || !reflect.DeepEqual(parsed, definitions) {
		return nil, fmt.Errorf("generated definitions cannot form an exact canonical header: %v", err)
	}
	return data, nil
}
