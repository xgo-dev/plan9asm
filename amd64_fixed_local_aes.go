package plan9asm

func fixedLocalAESByteStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	f, known, err := x86AESProperties(ins.Op, *ins, "amd64")
	if !known {
		return false, nil
	}
	if err != nil || f.byteWidth != 16 {
		return true, goAMD64FrameContext("fixed local AES shape is not closed")
	}
	width := uint64(65535)
	source := state.vectors[x86CallerVectorRoot(f.sourceOperand.Reg)] & width
	if f.memory >= 0 {
		if _, _, err := fixedLocalReadMemory(ins, f.memory, state, proof, residue, 16, 1); err != nil {
			return true, err
		}
		source = width
	}
	input := uint64(0)
	if f.state >= 0 {
		input = state.vectors[x86CallerVectorRoot(ins.Args[f.state].Reg)] & width
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	defined := x86AESDefinedBytes(f, source, input)
	if !f.spec.vector {
		state.vectors[destination] = state.vectors[destination]&^width | defined
	} else {
		state.vectors[destination] = ^width | defined
	}
	return true, nil
}
