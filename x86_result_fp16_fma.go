package plan9asm

func x86RawFP16FMASourceForm(ins Instr, arch string) (amd64FMA3Form, bool) {
	f, known, err := amd64FMA3Properties(ins, arch)
	return f, known && err == nil && f.spec.rawOnly && x86RawOrdinaryVectorSource(ins, arch)
}

// Only the paired lowerer may consume this conditional native result. Exact
// original source and all three numerical inputs remain required; this grants
// neither caller/backing authority nor a reusable memory or MXCSR fact.
func x86LoweredFP16FMAStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	f, known, _ := amd64FMA3Properties(ins, arch)
	if !known || !f.spec.rawOnly {
		return false, false
	}
	if _, valid := x86RawFP16FMASourceForm(ins, arch); !valid {
		return false, true
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	width := f.byteWidth
	if f.spec.scalar {
		width = f.spec.laneBits / 8
	}
	required := x86CallerVectorByteMask(int64(width))
	for _, index := range []int{0, 1, f.destination} {
		if index == f.memory {
			local := ins
			local.x86Encoded, local.x86SourceRaw = false, nil
			if !x86ResultReadWithNativeContinuation(local, ins.Args[index], int64(f.memoryBytes), state, owned, arch, true) {
				return false, true
			}
			continue
		}
		reg, _ := amd64VectorRegisterIndex(ins.Args[index].Reg, f.byteWidth)
		if state.vectorBytes(reg)&required != required {
			return false, true
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	value := ^uint64(0)
	if f.spec.scalar {
		value = required | state.vectorBytes(destination)&(0xffff&^required)
	}
	state.writeVector(destination, f.byteWidth, value, false)
	return true, true
}
