package plan9asm

// The strict observer and lowering-local raw/native continuations consume one
// scalar move byte effect. A captured physical form is never reparsed after
// provenance projection, especially for mode32's actual four-operand encoding.
func x86ScalarVectorMoveResultTransfer(ins Instr, form amd64ScalarVectorMoveForm,
	state *x86ResultState, owned []bool, resultOffset int64, arch string, native bool) bool {
	if form.spec.legacy || form.spec.rawOnly || form.spec.bits != 32 && form.spec.bits != 64 {
		return false
	}
	width := int64(form.spec.bits / 8)
	lowMask := uint16(1)<<uint(width) - 1
	xreg := func(operand Operand) (int, bool) {
		index, valid := amd64ParseXReg(operand.Reg)
		return index, operand.Kind == OpReg && valid && index < len(state.xmm) && (arch != "386" || index < 8)
	}
	if form.mask >= 0 {
		index, valid := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !valid || !state.masks[index] {
			return false
		}
	}
	first, last := ins.Args[form.low], ins.Args[form.destination]
	if source, valid := xreg(first); valid {
		if state.xmm[source]&lowMask != lowMask {
			return false
		}
	} else if !form.literal && !x86ResultReadWithNativeContinuation(ins, first, width, state, owned, arch, native) {
		return false
	}
	if form.memoryWrite {
		if native && x86ScalarVectorMoveOrdinaryMemory(last, form.spec.bits, arch) &&
			x86ResultIncomingPointerAddressIdentity(last, state, arch) {
			// The exact active native write never reads old destination bytes
			// and establishes no initialized logical or reusable memory fact.
			return true
		}
		if form.mask >= 0 {
			return x86ResultRead(last, width, state, owned, arch)
		}
		return x86ResultStore(last, width, state, owned, resultOffset, arch)
	}
	destination, valid := xreg(last)
	if !valid {
		return false
	}
	if form.mask >= 0 && !form.zeroing && state.xmm[destination]&lowMask != lowMask {
		return false
	}
	known := uint16(0xffff)
	if form.upper >= 0 {
		upper, valid := xreg(ins.Args[form.upper])
		if !valid {
			return false
		}
		known = state.xmm[upper]&^lowMask | lowMask
	}
	if form.mask >= 0 && !form.zeroing {
		known = known&^lowMask | known&state.xmm[destination]&lowMask
	}
	state.writeVector(destination, 16, uint64(known), false)
	return true
}
