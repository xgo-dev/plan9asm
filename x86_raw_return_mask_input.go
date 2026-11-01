package plan9asm

import "math"

// KMOV's logical FP reader gathers exactly its B/W/D/Q bytes, including
// interior and cross-field numeric parameter views. Their separately allocated
// storage cannot overlap the native return PC. This is only that memory-safety
// role: mask definedness, result reads and source initialization still belong
// to the complete numerical consumer. Stores and native pointers gain nothing.
func x86RawReturnMaskParameterReadBound(ins Instr, operand int, sig FuncSig, arch string) bool {
	if arch != "amd64" && arch != "386" || operand != 0 ||
		!x86ResultNamedPredicateInstruction(ins) || !amd64MaskMoveOperandsValid(ins, arch) ||
		ins.Args[0].Kind != OpFP || !amd64IsKOperand(ins.Args[1]) ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.WASMContext != "" || len(sig.Frame.Params) == 0 {
		return false
	}
	width := int64(amd64MaskMoveSpecs[ins.Op] / 8)
	offset := ins.Args[0].FPOffset
	if offset < 0 || width <= 0 || offset > math.MaxInt64-width {
		return false
	}
	// Reuse the existing full signature/field/extent/overlap validation once.
	// A touched prefix alone must not conceal a malformed unrelated slot.
	first := sig.Frame.Params[0]
	if !x86RawReturnFPBound(first.Offset, x86RawReturnSlotBytes(first.Type, arch), sig, arch) {
		return false
	}
	for current := offset; current < offset+width; current++ {
		matches := 0
		for _, slot := range sig.Frame.Params {
			if current < slot.Offset || current >= slot.Offset+x86RawReturnSlotBytes(slot.Type, arch) {
				continue
			}
			switch slot.Type {
			case I8, I16, I32, I64, LLVMType("float"), LLVMType("double"):
				matches++
			default:
				return false // Pointer/bool bytes are not this numerical input role.
			}
		}
		if matches != 1 {
			return false // Neither padding, a result nor an absent parameter is backing.
		}
	}
	return true
}
