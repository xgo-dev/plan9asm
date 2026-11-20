package plan9asm

import "strings"

// Go assembly's unqualified DATA names are package-local. Definitions and SB
// reads must resolve through this same namespace, including caller aliases.
func resolveAssemblyDataSymbol(sym string, resolve func(string) string) string {
	if !strings.ContainsAny(sym, "·/.") {
		sym = "·" + sym
	}
	return resolve(sym)
}
