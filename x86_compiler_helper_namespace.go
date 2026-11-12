package plan9asm

import (
	"fmt"
	"strings"
)

// Compiler-local naming only. Every original LLVM-reachable source name is
// reserved; this supplies no declaration, entry, storage or source authority.
func x86CompilerHelperNamespace(file *File, resolve func(string) string, sigs map[string]FuncSig, family string) string {
	var names []string
	reserve := func(symbol string) {
		names = append(names, symbol)
	}
	for name, sig := range sigs {
		// Signature keys and names are already final LLVM symbols.
		reserve(name)
		reserve(sig.Name)
	}
	for _, fn := range file.Funcs {
		name := resolve(fn.Sym)
		reserve(funcSigSymbol(name, sigs[name]))
		for _, ins := range fn.Instrs {
			for _, operand := range ins.Args {
				symbol := ""
				if operand.Kind == OpSym {
					symbol = strings.TrimSpace(strings.TrimPrefix(operand.Sym, "*"))
				} else if operand.Kind == OpMem {
					symbol = operand.Mem.Sym
				}
				if base, _, ok := parseSBRef(symbol); ok && base != "" {
					// Only SB identities can become LLVM globals; local branch
					// labels and FP/AUTO component names never reach ResolveSym.
					base = strings.TrimPrefix(base, "$")
					reserve(resolveDataAddressSymbol(file, base, resolve, sigs))
				}
			}
		}
	}
	for _, data := range file.Data {
		reserve(resolveDataSymbol(data.Sym, resolve))
		if data.Addr != "" {
			if symbol, _, err := dataAddress(data); err == nil {
				reserve(resolveDataAddressSymbol(file, symbol, resolve, sigs))
			}
		}
	}
	for _, global := range file.Globl {
		reserve(resolveDataSymbol(global.Sym, resolve))
	}
	for number := 0; ; number++ {
		prefix := fmt.Sprintf("__plan9asm_%s_%d_", family, number)
		collision := false
		for _, name := range names {
			if strings.Contains(name, prefix) {
				collision = true
				break
			}
		}
		if !collision {
			return prefix
		}
	}
}
