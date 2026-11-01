package plan9asm

func x86CallerFMA3Step(ins *Instr, form amd64FMA3Form, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.spec.rawOnly || form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return false
	}
	width := int64(form.byteWidth)
	if form.spec.scalar {
		width = int64(form.spec.laneBits / 8)
	}
	required := x86CallerVectorByteMask(width)
	if form.memory >= 0 && !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.memoryBytes), false) {
		return false
	}
	// All three operands participate in every order, including the old
	// destination in zeroing forms. An initialized unknown-valued mask is
	// not a proof of inactive lanes; arithmetic cannot invent missing bytes.
	for _, index := range []int{0, 1, form.destination} {
		if index == form.memory {
			continue
		}
		root := x86CallerVectorRoot(ins.Args[index].Reg)
		if state.vectors[root]&required != required {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	known := ^uint64(0)
	if form.spec.scalar {
		// Scalar FMA preserves the old destination's remaining XMM bytes,
		// independently of its low-lane mask, and zeroes higher Y/Z aliases.
		upperX := x86CallerVectorByteMask(16) &^ required
		known = ^x86CallerVectorByteMask(16) | required | state.vectors[destination]&upperX
	}
	state.vectors[destination] = known
	return true
}
