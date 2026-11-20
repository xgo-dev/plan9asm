package plan9asm

// A single adjacent native store may observe these address-derived bytes.
// They are not numerical inputs, canonical bools, pointers or backing facts.
// Every other successful effect revokes this short-lived observation.
type x86NativeLEAAddressBits struct {
	register uint8
	bytes    uint8
}

func x86ResultNativeLEAAddressBitsStep(ins Instr, state *x86ResultState, owned []bool,
	arch string, leaf bool) (bool, bool) {
	effect, known, err := x86TypedLEAByteEffect(ins.Op, ins, arch)
	if !known || err != nil {
		return false, false // Existing physical, stack and malformed-source consumers remain separate.
	}
	output := effect.operands[len(effect.operands)-1]
	if output.width >= x86ResultPointerWord(arch) {
		return false, false // Preserve the existing full-word incoming-pointer continuation.
	}
	address := false
	for _, operand := range effect.operands {
		if !operand.read {
			continue
		}
		register, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
		if valid && state.callerAddressGP[register] {
			address = true
		} else if !x86ResultRead(operand.operand, operand.width, state, owned, arch) {
			return false, true
		}
	}
	if !address {
		return false, false // Do not intercept the complete existing pure-numerical LEA rule.
	}
	if !leaf || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	register, mask, valid := x86ResultGP(output.operand.Reg, output.width, arch)
	if !valid {
		return false, true
	}
	observed := mask
	if output.width == 2 && state.callerAddressGP[register] {
		// LEAW leaves the old destination's high bytes unchanged. An
		// actual caller-address identity already supplies their observable
		// representation, not NUM or a new pointer. Retain those bytes only
		// in this same adjacent-store carrier; LEAL instead zeroes upper32.
		observed = x86CallerByteMask(output.operand.Reg, x86ResultPointerWord(arch))
	}
	state.gp[register] &^= mask
	state.canonicalGP[register] &^= mask
	state.pointerGP[register] = false
	if output.width == 4 {
		// The architectural upper32 zero is numerical; the low address
		// bytes remain in the disjoint one-store observation domain.
		state.gp[register] = 0xf0
		state.canonicalGP[register] |= 0xf0
	}
	state.nativeLEAAddressBits = x86NativeLEAAddressBits{uint8(register), observed}
	return true, true
}
