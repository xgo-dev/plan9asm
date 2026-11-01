package plan9asm

// The complete GP/X grammar owns widths and aliases. This consumer supplies
// only the existing numerical register, private/native memory and FP roles;
// it does not turn relocated or opaque addresses into numerical vector bytes.
func fixedLocalGPSIMDTransferStep(ins *Instr, state *x86FixedLocalState, sig FuncSig,
	proof *x86FixedLocalProof, residue int) (bool, error) {
	form, recognized, err := x86GPSIMDTransferProperties(*ins, "amd64")
	if !recognized || err != nil {
		return recognized, err
	}
	fail := func() (bool, error) {
		return true, goAMD64FrameContext("fixed local GP/X transfer lacks numerical bytes or a bound storage role")
	}
	if form.mmx || form.spec.rawOnly {
		return fail()
	}
	width := int64(form.bits / 8)
	low := x86CallerVectorByteMask(width)
	var known uint64
	if form.sourceX {
		known = state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)] & low
	} else if form.memory < 0 {
		root, valid := x86CallerGP(ins.Args[0].Reg)
		_, private := state.pointers[root]
		_, opaque := state.opaque[root]
		if ins.Args[0].Kind != OpReg || !valid || root == SP || private || opaque {
			return fail()
		}
		known = uint64(state.known[root]) & low
	} else {
		value, err := fixedLocalReadValue(ins, 0, state, sig, proof, residue, width, false)
		if err != nil {
			return true, err
		}
		if value.pointer || value.opaque {
			return fail()
		}
		known = low // Memory and FP inputs require their complete numerical role.
	}
	if form.destinationX {
		root := x86CallerVectorRoot(ins.Args[1].Reg)
		state.vectors[root] = form.definedVectorBytes(known, state.vectors[root])
		return true, nil
	}
	if ins.Args[1].Kind != OpReg && known != low {
		return fail() // An unknown stored byte cannot initialize memory or FP.
	}
	if err := fixedLocalWriteValue(ins, 1, 0, fixedLocalScalarValue{}, state, sig, proof, residue, width); err != nil {
		return true, err
	}
	if ins.Args[1].Kind == OpReg {
		root, _ := x86CallerGP(ins.Args[1].Reg)
		// Replace old facts even for unknown inputs; dword GP writes define
		// the upper dword as zero. The shared writer revoked address/value facts.
		state.known[root] = uint8(known) | ^uint8(low)
	}
	return true, nil
}
