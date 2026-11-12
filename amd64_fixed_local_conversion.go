package plan9asm

// This normalizes the existing complete conversion grammars for the private
// frame observer. It grants neither caller storage nor a physical MMX role.
type x86FixedLocalConversion struct {
	inputBytes, outputBytes, activeBytes int
	memoryBytes, memory, destination     int
	mask                                 int
	legacy, zeroing, mmx                 bool
}

func fixedLocalConversionProperties(ins Instr) (x86FixedLocalConversion, bool, error) {
	if form, known, err := x86SignedPackedFloatProperties(ins, "amd64"); known {
		return x86FixedLocalConversion{
			inputBytes: form.inputBytes, outputBytes: form.byteWidth,
			activeBytes: form.byteWidth, memoryBytes: form.memoryBytes,
			memory: form.memory, destination: form.destination, mask: form.mask,
			legacy: form.spec.legacy, zeroing: form.zeroing, mmx: form.mmx,
		}, true, err
	}
	form, known, err := x86PackedConversionProperties(ins, "amd64")
	return x86FixedLocalConversion{
		inputBytes: form.inputBytes, outputBytes: form.shape.destinationBytes,
		activeBytes: form.shape.lanes * form.spec.destinationBits / 8,
		memoryBytes: form.memoryBytes, memory: form.memory,
		destination: form.destination, mask: form.mask,
		legacy: form.spec.legacy, zeroing: form.properties.zeroing, mmx: form.mmx,
	}, known, err
}

func fixedLocalConversionStep(ins *Instr, state *x86FixedLocalState, proof *x86FixedLocalProof, residue int) (bool, error) {
	form, known, err := fixedLocalConversionProperties(*ins)
	if !known {
		return false, nil
	}
	if err != nil || form.mmx {
		return true, goAMD64FrameContext("fixed local conversion lacks an ordinary physical vector shape")
	}
	if form.mask >= 0 && !state.masks[ins.Args[form.mask].Reg] {
		return true, goAMD64FrameContext("fixed local conversion has an undefined mask")
	}
	if form.memory >= 0 {
		// Legacy m128 retains its alignment requirement. CVTDQ2PD m64
		// and VEX/EVEX have no corresponding 16-byte #GP requirement.
		alignment := int64(1)
		if form.legacy && form.memoryBytes == 16 {
			alignment = 16
		}
		if _, _, err := fixedLocalReadMemory(ins, form.memory, state, proof, residue,
			int64(form.memoryBytes), alignment); err != nil {
			return true, err
		}
	} else {
		input := state.vectors[x86CallerVectorRoot(ins.Args[0].Reg)]
		required := x86CallerVectorByteMask(int64(form.inputBytes))
		if input&required != required {
			return true, goAMD64FrameContext("fixed local conversion reads undefined numerical bytes")
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	active := x86CallerVectorByteMask(int64(form.activeBytes))
	if form.mask >= 0 && !form.zeroing && state.vectors[destination]&active != active {
		return true, goAMD64FrameContext("fixed local conversion merges undefined destination bytes")
	}
	// Narrowing explicitly clears its carrier padding. Legacy preserves
	// wider aliases; VEX/EVEX clears them. Integer FLAGS remain unchanged.
	if form.legacy {
		state.vectors[destination] |= x86CallerVectorByteMask(int64(form.outputBytes))
	} else {
		state.vectors[destination] = ^uint64(0)
	}
	return true, nil
}
