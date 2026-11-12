package plan9asm

import "strings"

// A prepared root seals its cloned instructions, not mutable siblings or DATA.
// Reaudit the complete supplied file on every preparation/final API entry. All
// three source-continuation families remove a native TEXT identity; none may
// regain that identity through newly added source after its initial audit.
func validateARM64PrivateContinuationFile(file *File) error {
	removed := make(map[string]bool)
	hasCallContinuation := false
	add := func(helpers []Func) {
		for _, helper := range helpers {
			removed[helper.Sym] = true
		}
	}
	for _, fn := range file.Funcs {
		if proof := fn.arm64PrivateCallSource; proof != nil {
			hasCallContinuation = true
			add(proof.helpers)
		}
		if proof := fn.arm64PrivateTailSource; proof != nil {
			add(proof.helpers)
		}
		if proof := fn.arm64ABI0TailSource; proof != nil {
			add(proof.helpers)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if len(file.UnlinkedPrelude) != 0 {
		return arm64GoABIContext("private continuation file has an unbound native prelude")
	}
	refersToRemoved := func(symbol string) bool {
		base, _, ok := arm64PrivateSymbolRef(symbol)
		return ok && removed[base]
	}
	for _, data := range file.Data {
		if refersToRemoved(data.Sym) || refersToRemoved(data.Addr) {
			return arm64GoABIContext("private continuation file recovers a removed helper through DATA")
		}
	}
	for _, global := range file.Globl {
		if refersToRemoved(global.Sym) {
			return arm64GoABIContext("private continuation file recovers a removed helper through GLOBL")
		}
	}
	for _, fn := range file.Funcs {
		if removed[fn.Sym] {
			return arm64GoABIContext("private continuation file redefines removed helper %q", fn.Sym)
		}
		for _, ins := range fn.Instrs {
			// Tail-only files independently exclude native PC/raw/address
			// observers below, so validated NOP padding has no data effect.
			// CALL continuations retain their stricter layout contract.
			if _, alignment, err := arm64PCAlignment(ins); alignment && (err != nil || hasCallContinuation) {
				return arm64GoABIContext("private continuation file has unproved alignment at %q", ins.Raw)
			}
			switch ins.Op {
			case OpWORD, "DWORD", "ADR", "ADRP":
				return arm64GoABIContext("private continuation file observes native layout at %q", ins.Raw)
			}
			for _, arg := range ins.Args {
				memory, hasMemory := arg.Mem, arg.Kind == OpMem
				if arg.Kind == OpSym && strings.HasPrefix(arg.Sym, "$") {
					memory, hasMemory = parseMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$")))
				}
				if hasMemory && (memory.Base == PC || refersToRemoved(memory.Sym)) {
					return arm64GoABIContext("private continuation file has a native PC/removed-helper memory use at %q", ins.Raw)
				}
				if arg.Kind == OpSym && refersToRemoved(arg.Sym) {
					return arm64GoABIContext("private continuation file recovers removed helper identity at %q", ins.Raw)
				}
			}
		}
	}
	return nil
}
