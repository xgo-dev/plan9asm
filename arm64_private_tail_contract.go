package plan9asm

import "strings"

func arm64PrivateTailSymbol(symbol string) bool {
	base, _, ok := parseSBRef(strings.TrimSpace(symbol))
	return ok && strings.HasSuffix(goTextSymbolForResolution(base), "<>")
}

// A standalone private source helper does not share its caller's virtual GP
// registers or FP allocations. An ordinary Frame, even with identical Go
// argument/result types, is not a source-register transport contract.
func arm64ValidatePrivateTailTransport(symbol string, sig FuncSig, present bool) error {
	if !arm64PrivateTailSymbol(symbol) {
		return nil
	}
	_, offset, _ := parseSBRef(symbol)
	if offset != 0 {
		return arm64GoABIContext("private tail %q has no entry contract for a symbol offset", symbol)
	}
	if !present || len(sig.ArgRegs) == 0 || len(sig.ArgRegs) != len(sig.Args) {
		return arm64GoABIContext("private tail %q requires an explicit complete register transport, not its caller's Frame", symbol)
	}
	for i, reg := range sig.ArgRegs {
		_, floating := arm64ParseFReg(reg)
		if arm64MachineScalarWidth(sig.Args[i]) == 0 ||
			!floating && !isARM64GeneralOrZeroReg(reg) && !arm64StackReg(reg) {
			return arm64GoABIContext("private tail %q has an unproved register/type at argument %d", symbol, i)
		}
	}
	return nil
}
