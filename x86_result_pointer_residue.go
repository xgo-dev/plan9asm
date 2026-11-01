package plan9asm

// A proper low-bit AND projection may observe an actual incoming caller
// address, not an arbitrary opaque pointer carrier. Both independent reaching
// identities must survive; neither a literal/OR carrier nor NUM bytes supply
// them. This consumes the complete existing Go AND immediate/register grammar,
// including encoded immediates and physical byte aliases. No source, native
// entry, backing, extent, alignment or reusable address permission follows.
func x86ResultPointerResidueStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	if state.shapeOnly || !x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known || err != nil || form.spec.stem != "AND" || form.source.Kind != OpImm || form.destination.Kind != OpReg {
		return false, false
	}
	width := int64(form.spec.bits / 8)
	index, _, valid := x86ResultGP(form.destination.Reg, width, arch)
	if !valid || !state.pointerGP[index] || !state.callerAddressGP[index] {
		return false, false
	}
	mask, all := uint64(form.source.Imm), ^uint64(0)
	if form.spec.bits < 64 {
		all = uint64(1)<<uint(form.spec.bits) - 1
	}
	if form.source.Imm < 0 || mask >= all || mask&(mask+1) != 0 {
		return false, false // Identity/sparse transforms retain their old opaque role.
	}
	if !x86ResultStore(form.destination, width, state, owned, resultOffset, arch) {
		return false, true
	}
	// Partial writes define only their bytes; L clears the upper32. The old
	// full-word pointer and all address aliases are revoked even for B/W.
	state.callerAddressGP[index], state.pointerGP[index] = false, false
	state.callerAddressOrigin[index] = 0
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	state.canonicalGP[index] = 0
	state.predicate = x86ResultPredicate{}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}
