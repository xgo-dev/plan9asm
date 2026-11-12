package plan9asm

// Reuse the complete scalar-lane grammar, including Go's GP-number spellings.
// This owner binds only low physical X registers and ordinary memory. Logical
// FP fields and EVEX high banks retain their independent entry contracts.
func fixedLocalScalarLaneProperties(ins Instr) (x86ScalarLaneForm, bool, error) {
	form, known, err := x86ScalarLaneProperties(ins, "amd64")
	if !known {
		return form, false, nil
	}
	valid := err == nil
	if valid && form.memory >= 0 {
		kind := ins.Args[form.memory].Kind
		valid = kind == OpMem || kind == OpSym
	}
	if valid {
		vectors := [2]int{form.source, -1}
		if form.insert {
			vectors = [2]int{form.base, form.destination}
		}
		for _, index := range vectors {
			if index >= 0 {
				register, physical := amd64ParseXReg(ins.Args[index].Reg)
				valid = valid && physical && register < 16
			}
		}
	}
	if !valid {
		return form, true, goAMD64FrameContext("fixed local scalar-lane form lacks a bound physical role: %s", ins.Op)
	}
	return form, true, nil
}

func fixedLocalScalarLaneStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	form, known, err := fixedLocalScalarLaneProperties(*ins)
	if !known || err != nil {
		return known, err
	}
	width := int64(form.bits / 8)
	selected := x86CallerVectorByteMask(width)
	if form.insert {
		if form.memory >= 0 {
			// Scalar m8/m16/m32/m64 accesses stay exact and unaligned. Their
			// native volatile emitter does not grant future pointee facts.
			if _, _, err := fixedLocalReadMemory(ins, form.memory, state, proof, residue, width, 1); err != nil {
				return true, err
			}
		} else if !fixedLocalNumericRead(Operand{Kind: OpReg, Reg: form.transferReg}, width, state) {
			return true, goAMD64FrameContext("fixed local scalar insert reads undefined or address bytes")
		}
		base := state.vectors[x86CallerVectorRoot(ins.Args[form.base].Reg)]
		destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
		state.vectors[destination] = x86ScalarLaneInsertKnown(form, base, selected, state.vectors[destination])
		return true, nil
	}
	source := state.vectors[x86CallerVectorRoot(ins.Args[form.source].Reg)]
	if source>>uint(form.offset)&selected != selected {
		return true, goAMD64FrameContext("fixed local scalar extract reads undefined selected bytes")
	}
	if form.memory >= 0 {
		offset, role, err := fixedLocalMemoryAccess(ins, form.memory, state, proof, residue, width, 1, true, false)
		if err != nil {
			return true, err
		}
		if role == x86FixedLocalPrivateMemory {
			fixedLocalNumericalStore(state, offset, width, true)
		}
		return true, nil
	}
	// GP extraction reuses the ordinary dword/qword writer, including zero
	// extension and revocation of constants, booleans and address identities.
	effect := x86TypedByteEffect{operands: []x86TypedByteOperand{{
		index: form.destination, operand: Operand{Kind: OpReg, Reg: form.transferReg},
		width: int64(form.gpBits / 8), write: true,
	}}}
	return true, fixedLocalTypedByteStep(ins, state, FuncSig{}, proof, residue, effect)
}
