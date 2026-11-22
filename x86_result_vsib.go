package plan9asm

// VSIB numerical continuation requires the actual index, mask and merge/data
// inputs. A paired indexed access may supply active loaded bytes on normal
// continuation; it creates no contiguous extent, frame or later-read fact.
func x86ResultVSIBStep(ins Instr, state *x86ResultState, arch string, native, dataBP bool) (bool, bool) {
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
	if !native || !x86ResultVSIBAddress(form.memory, state, arch, dataBP) {
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

// With no encoded GP base, the initialized vector index and displacement
// supply the full numerical address. This proves only the architectural
// inputs to the paired predicated access. In particular, the access may fault.
func x86ResultVSIBAddress(address Operand, state *x86ResultState, arch string, dataBP bool) bool {
	if address.Mem.Segment != "" {
		return false
	}
	if address.Mem.Base == "" {
		return true
	}
	if arch == "amd64" && address.Mem.Base == BP {
		// Only the saved-BP leaf scope may use its reaching pointer fact.
		// SP and the physical entry BP retain their independent frame roles.
		return dataBP && (state.shapeOnly || state.pointerGP[5])
	}
	if !x86OrdinaryNativeMemoryOperand(address, arch) {
		return false
	}
	address.Mem.Index, address.Mem.Scale = "", 0
	return x86ResultIncomingPointerAddressIdentity(address, state, arch)
}

// The ordinary scratch fallback seeds entire vector slots. An index-only
// data operation must get its address, predicate and merge/data from the
// reaching source state, including when a prior vector operation made them.
func x86ResultHasIndexOnlyVSIB(fn Func, arch string) bool {
	for _, ins := range fn.Instrs {
		if form, known, err := x86VSIBProperties(ins, arch); known && err == nil &&
			!form.prefetch && form.memory.Mem.Base == "" {
			return true
		}
	}
	return false
}
