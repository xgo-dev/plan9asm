package plan9asm

import "fmt"

// Source labels and generated entry/fallthrough blocks are different roles.
// Keep every source alias, and reserve fresh synthetic names before CFG
// construction instead of guessing a role from a source-name prefix.
type assemblyBlockNames struct {
	used map[string]bool
}

func newAssemblyBlockNames(function Func) *assemblyBlockNames {
	names := &assemblyBlockNames{used: make(map[string]bool)}
	for _, instruction := range function.Instrs {
		if instruction.Op == OpLABEL && len(instruction.Args) == 1 && instruction.Args[0].Kind == OpLabel {
			names.used[instruction.Args[0].Sym] = true
		}
	}
	return names
}

func (names *assemblyBlockNames) fresh(prefix string) string {
	name := prefix
	for suffix := 1; names.used[name]; suffix++ {
		name = fmt.Sprintf("%s_%d", prefix, suffix)
	}
	names.used[name] = true
	return name
}
