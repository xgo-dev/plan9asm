package plan9asm

// VSIB numerical continuation requires the actual index, mask and merge/data
// inputs. A paired indexed access may supply active loaded bytes on normal
// continuation; it creates no contiguous extent, frame or later-read fact.
func x86ResultVSIBStep(ins Instr, state *x86ResultState, arch string, native bool) (bool, bool) {
	form, known, err := x86VSIBProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return false, true
	}
	if form.prefetch {
		return true, true // The existing emitter elides this hint, with no data or state result.
	}
	index, valid := amd64VectorRegisterIndex(form.memory.Mem.Index, form.indexBytes)
	indexRequired := x86CallerVectorByteMask(int64(form.indexBytes))
	if !valid || state.vectorBytes(index)&indexRequired != indexRequired {
		return false, true
	}
	data, valid := amd64VectorRegisterIndex(form.data.Reg, form.dataBytes)
	required := x86CallerVectorByteMask(int64(form.dataBytes))
	if !valid || arch == "386" && data >= 8 || state.vectorBytes(data)&required != required {
		return false, true // Gather retains inactive merge lanes; scatter reads active data.
	}
	mask := 0
	if form.evex {
		mask, valid = amd64ParseKReg(form.mask.Reg)
		if !valid || !state.masks[mask] {
			return false, true
		}
	} else {
		mask, valid = amd64VectorRegisterIndex(form.mask.Reg, form.dataBytes)
		if !valid || arch == "386" && mask >= 8 || state.vectorBytes(mask)&required != required {
			return false, true
		}
	}
	if !native || !x86OrdinaryNativeMemoryOperand(form.memory, arch) {
		return false, true
	}
	// Check the independent typed pointer base after consuming the numerical
	// vector index. A vector index is not an ordinary GP or a contiguous tuple.
	base := form.memory
	base.Mem.Index, base.Mem.Scale = "", 0
	if !x86ResultIncomingPointerAddressIdentity(base, state, arch) {
		return false, true
	}
	if !form.scatter {
		state.writeVector(data, form.dataBytes, required, false)
	}
	if form.evex {
		state.masks[mask] = true // A normally completed gather/scatter clears its K mask.
	} else {
		state.writeVector(mask, form.dataBytes, required, false)
	}
	return true, true
}
