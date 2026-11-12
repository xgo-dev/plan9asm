package plan9asm

// One adjacent consumer may project partially defined GP bits from a typed
// producer. This replaces the POP-only observation, not a per-register bit
// domain. Every intervening instruction consumes it, including branches.
// Stack origins remain separate from numerical bit availability.
type x86ResultGPBits struct {
	bits      uint64
	register  int
	valid     bool
	fromStack bool // Only a real POP can consume the private FLAGS-origin relation.
}

func x86ResultGPBitsMaskStep(ins Instr, pending x86ResultGPBits, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if !pending.valid || !x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	var source, destination Operand
	var width int64
	var killed, defined uint8
	readOnly := false
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil &&
		form.spec.stem == "AND" && form.source.Kind == OpImm && form.destination.Kind == OpReg {
		source, destination, width = form.source, form.destination, int64(form.spec.bits/8)
		killed, defined = form.spec.flagsKilled, form.spec.flagsDefined
	} else if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil &&
		form.test && form.args[0].Kind == OpImm && form.args[1].Kind == OpReg {
		source, destination, width = form.args[0], form.args[1], int64(form.bits/8)
		killed, defined, readOnly = x86ByteFlagsAll, x86ByteFlagsAll&^x86ByteFlagAF, true
	} else {
		return false, false
	}
	index, bytes, valid := x86ResultGP(destination.Reg, width, arch)
	if !valid || index != pending.register || x86LogicalSourceFrameRegister(destination.Reg, arch) {
		return false, false
	}
	shift := uint(0)
	if width == 1 && bytes == 2 {
		shift = 8 // AH/CH/DH/BH select the second physical byte.
	}
	mask := uint64(source.Imm)
	if width < 8 {
		mask &= uint64(1)<<uint(8*width) - 1
	}
	if mask&^(pending.bits>>shift) != 0 {
		return false, true // Unselected unknown bits do not become numerical.
	}
	if !readOnly && !x86ResultStore(destination, width, state, owned, resultOffset, arch) {
		return false, true
	}
	state.flags = state.flags&^killed | defined
	return true, true // TEST never writes the unobserved GP bits.
}
