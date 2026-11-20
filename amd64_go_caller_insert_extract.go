package plan9asm

func x86CallerInsertExtractStep(ins *Instr, f x86InsertExtractForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if f.mask >= 0 && !state.masks[ins.Args[f.mask].Reg] || f.mask >= 0 && f.memoryWrite {
		return false
	}
	if f.memory >= 0 && !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.spec.chunk), f.memoryWrite) {
		return false
	}
	source := state.vectors[x86CallerVectorRoot(ins.Args[f.source].Reg)]
	low := x86CallerVectorByteMask(int64(f.spec.chunk))
	if !f.spec.insert {
		if source>>uint(f.offset)&low != low {
			return false
		}
		if f.memoryWrite {
			return true
		}
		if f.spec.scalar {
			return x86CallerNumericWrite(ins.Args[f.destination].Reg, 8, state)
		}
		known := low
		destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
		if f.mask >= 0 && !f.zeroing {
			known &= state.vectors[destination]
		}
		state.vectors[destination] = ^low | known
		return true
	}
	base := state.vectors[x86CallerVectorRoot(ins.Args[f.base].Reg)]
	outputMask := x86CallerVectorByteMask(int64(f.output))
	if f.spec.scalar {
		insertLane := int(f.immediate>>4) & 3
		insertMask := uint64(15) << uint(insertLane*4)
		knownSource := source >> uint((f.immediate>>6)*4) & 15
		if f.memory >= 0 {
			knownSource = 15
		}
		known := base&^insertMask | knownSource<<uint(insertLane*4)
		for lane := 0; lane < 4; lane++ {
			if f.immediate&(1<<lane) != 0 {
				known |= uint64(15) << uint(lane*4)
			}
		}
		upper := ^outputMask
		if f.spec.legacy {
			upper &= state.vectors[x86CallerVectorRoot(ins.Args[f.destination].Reg)]
		}
		state.vectors[x86CallerVectorRoot(ins.Args[f.destination].Reg)] = upper | known&outputMask
		return true
	}
	if f.memory < 0 && source&low != low {
		return false
	}
	insertMask := low << uint(f.offset)
	known := base&^insertMask | insertMask
	if f.mask >= 0 && !f.zeroing {
		known &= state.vectors[x86CallerVectorRoot(ins.Args[f.destination].Reg)]
	}
	state.vectors[x86CallerVectorRoot(ins.Args[f.destination].Reg)] = ^outputMask | known&outputMask
	return true
}
