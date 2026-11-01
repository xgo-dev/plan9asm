package plan9asm

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// This is an immutable compiler declaration catalog, not a source, SDK or
// caller observation. Construct it once; each module selects its own used set.
var arm64PreludeCatalog struct {
	once         sync.Once
	declarations map[string]string
}

func emitUsedARM64Prelude(b *strings.Builder) {
	arm64PreludeCatalog.once.Do(func() {
		var catalog strings.Builder
		emitARM64Prelude(&catalog)
		arm64PreludeCatalog.declarations = llvmPreludeDeclarations(catalog.String())
	})
	emitUsedLLVMPrelude(b, arm64PreludeCatalog.declarations)
}

// The input is the compiler's existing declaration emitter, not source IR.
func llvmPreludeDeclarations(text string) map[string]string {
	declarations := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "declare ") {
			continue
		}
		start := strings.IndexByte(line, '@') + 1
		end := strings.IndexByte(line[start:], '(') + start
		declarations[line[start:end]] = line
	}
	return declarations
}

func emitUsedLLVMPrelude(b *strings.Builder, declarations map[string]string) {
	var names []string
	for name := range llvmTextGlobalNames(b.String()) {
		if _, ok := declarations[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		b.WriteString(declarations[name])
		b.WriteByte('\n')
	}
}

// llvmTextGlobalNames scans generated LLVM text, not assembly opcodes. This
// includes raw/named lowerers and new intrinsic families without maintaining a
// second instruction registry. Comments and string constants are not uses.
func llvmTextGlobalNames(text string) map[string]bool {
	names := make(map[string]bool)
	for i := 0; i < len(text); {
		switch text[i] {
		case ';':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case '"':
			_, i = llvmTextQuotedName(text, i)
		case '@':
			i++
			if i < len(text) && text[i] == '"' {
				var name string
				name, i = llvmTextQuotedName(text, i)
				names[name] = true
				continue
			}
			start := i
			for i < len(text) && llvmTextNameByte(text[i]) {
				i++
			}
			if i > start {
				names[text[start:i]] = true
			}
		default:
			i++
		}
	}
	return names
}

func llvmTextNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '_' || c == '.' || c == '$' || c == '-'
}

func llvmTextQuotedName(text string, start int) (string, int) {
	var name strings.Builder
	for i := start + 1; i < len(text); i++ {
		if text[i] == '"' {
			return name.String(), i + 1
		}
		if text[i] == '\\' && i+2 < len(text) {
			if value, err := strconv.ParseUint(text[i+1:i+3], 16, 8); err == nil {
				name.WriteByte(byte(value))
				i += 2
				continue
			}
		}
		name.WriteByte(text[i])
	}
	// Malformed generated IR is still rejected by the LLVM parser. This scan
	// cannot turn an unterminated quoted identifier into a valid declaration.
	return "", len(text)
}
