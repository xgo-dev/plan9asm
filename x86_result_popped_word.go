package plan9asm

// A single adjacent numerical consumer may project the actual popped bits.
// Keeping this ephemeral observation avoids a full per-bit GP domain. Every
// other instruction consumes/revokes it, including branches, calls and writes.
type x86ResultPoppedWord struct {
	bits     uint64
	register int
	valid    bool
}

func x86ResultPoppedWordMaskStep(ins Instr, popped x86ResultPoppedWord, state *x86ResultState,
	owned []bool, resultOffset int64, arch string) (bool, bool) {
	if !popped.valid || !x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || form.spec.stem != "AND" ||
		form.source.Kind != OpImm || form.destination.Kind != OpReg {
		return false, false
	}
	width := int64(form.spec.bits / 8)
	index, bytes, valid := x86ResultGP(form.destination.Reg, width, arch)
	if !valid || index != popped.register || x86LogicalSourceFrameRegister(form.destination.Reg, arch) {
		return false, false
	}
	shift := uint(0)
	if width == 1 && bytes == 2 {
		shift = 8 // AH/CH/DH/BH select the second physical byte.
	}
	mask := uint64(form.source.Imm)
	if width < 8 {
		mask &= uint64(1)<<uint(8*width) - 1
	}
	if mask&^(popped.bits>>shift) != 0 {
		return false, true // No invented PF/AF/DF/ID or other unknown data bits.
	}
	if !x86ResultStore(form.destination, width, state, owned, resultOffset, arch) {
		return false, true
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}
