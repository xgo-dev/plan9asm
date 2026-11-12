package plan9asm

import (
	"strings"
	"sync"
)

// Only immutable compiler declarations are shared. Source-dependent helpers
// and all source/caller permissions remain local to the current translation.
var amd64DemandPreludeCatalog [2]struct {
	once         sync.Once
	declarations map[string]string
	ordinary     string
}

func amd64PreludeForGOARCH(goarch string) (map[string]string, string) {
	index := 0
	if goarch == "386" {
		index = 1
	}
	catalog := &amd64DemandPreludeCatalog[index]
	catalog.once.Do(func() {
		var full strings.Builder
		// The original emitter inspects file.Funcs for SHA/string/rounding
		// helpers. An empty file selects only its fixed declarations.
		emitAMD64Prelude(&full, goarch, &File{Arch: ArchAMD64})
		text := full.String()
		catalog.declarations = llvmPreludeDeclarations(text)
		var ordinary strings.Builder
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "declare ") && !strings.Contains(line, "@llvm.") {
				ordinary.WriteString(line)
				ordinary.WriteByte('\n')
			}
		}
		for name := range catalog.declarations {
			if !strings.HasPrefix(name, "llvm.") {
				delete(catalog.declarations, name)
			}
		}
		catalog.ordinary = ordinary.String()
	})
	return catalog.declarations, catalog.ordinary
}

func emitAMD64SourcePrelude(b *strings.Builder, file *File, goarch string) {
	_, ordinary := amd64PreludeForGOARCH(goarch)
	emitX86SHADeclarations(b, file)
	b.WriteString(ordinary)
	emitX86StringHelpers(b, file)
	emitAMD64FMA3RoundingHelpers(b, file, goarch)
}

func emitUsedAMD64Prelude(b *strings.Builder, goarch string) {
	declarations, _ := amd64PreludeForGOARCH(goarch)
	emitUsedLLVMPrelude(b, declarations)
}
