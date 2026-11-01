package plan9asm

import (
	"reflect"
	"strings"
)

// An ordinary external tail is a separate typed call+return, never a helper
// ABI or a native frame grant. Root argument/result roles must match exactly.
func (graph *x86DirectTailGraph) ordinaryExternalTail(root int, symbol string) bool {
	if root < 0 || root >= len(graph.original.Funcs) || strings.Contains(symbol, "<") ||
		strings.Contains(symbol, "*") || strings.Contains(graph.original.Funcs[root].Sym, "<") {
		return false
	}
	rootSig, rootKnown := graph.signatures[graph.symbols[graph.original.Funcs[root].Sym]]
	calleeName, known := graph.symbols[symbol]
	if !known {
		calleeName, known = graph.externalSymbols[symbol]
	}
	calleeSig, calleeKnown := graph.signatures[calleeName]
	if !rootKnown || !known || calleeName == "" || !calleeKnown || len(rootSig.ArgRegs) != 0 || len(calleeSig.ArgRegs) != 0 ||
		rootSig.ARMEntry != nil || calleeSig.ARMEntry != nil || rootSig.WASMContext != "" || calleeSig.WASMContext != "" ||
		len(rootSig.Frame.Results) == 0 || len(calleeSig.Frame.Results) == 0 ||
		calleeSig.Name != "" && calleeSig.Name != calleeName {
		return false
	}
	role := func(sig FuncSig) FuncSig {
		sig.Name = ""
		sig.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
		sig.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
		for index := range sig.Frame.Params {
			sig.Frame.Params[index].Name = "" // Descriptive, never a physical role.
		}
		for index := range sig.Frame.Results {
			sig.Frame.Results[index].Name = ""
		}
		return sig
	}
	return reflect.DeepEqual(role(rootSig), role(calleeSig))
}
