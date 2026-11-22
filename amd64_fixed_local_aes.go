package plan9asm

func fixedLocalAESByteStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	f, known, err := x86AESProperties(ins.Op, *ins, "amd64")
	if !known {
		return false, nil
	}
	if err != nil {
		return true, goAMD64FrameContext("fixed local AES shape is not closed")
	}
	bytes := int64(f.byteWidth)
	width := x86CallerVectorByteMask(bytes)
	source := state.vectors[x86CallerVectorRoot(f.sourceOperand.Reg)] & width
	if f.memory >= 0 {
		alignment := int64(16) // Only legacy AES carries the SSE alignment fault.
		if f.spec.vector {
			alignment = 1
		}
		if _, _, err := fixedLocalReadMemory(ins, f.memory, state, proof, residue, bytes, alignment); err != nil {
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
		state.setVectorBytes(destination, state.vectors[destination]&^width|defined)
	} else {
		state.setVectorBytes(destination, ^width|defined)
	}
	return true, nil
}
