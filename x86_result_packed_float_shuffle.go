package plan9asm

// The standalone observer supplies no native input or raw producer permission.
// The lowering-paired observer consumes the exact unconditional E4NF tuple;
// continuing past the original access establishes no future memory validity.
func x86ResultPackedFloatShuffleStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86PackedFloatShuffleProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	var first uint64
	if f.memory >= 0 {
		source := ins.Args[f.first]
		if f.legacy && source.Kind == OpFP ||
			!x86ResultReadWithNativeContinuation(ins, source, int64(f.memoryBytes), state, owned, arch, native) {
			return false, true
		}
		first = x86CallerVectorByteMask(int64(f.memoryBytes))
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[f.first].Reg, f.byteWidth)
		first = state.vectorBytes(index)
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[f.second].Reg, f.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	defined := f.definedBytes(first, state.vectorBytes(second), state.vectorBytes(destination))
	if f.memory >= 0 && native && defined != x86CallerVectorByteMask(int64(f.byteWidth)) {
		return false, true // Dead native reads cannot invent selected/merging input bytes.
	}
	state.writeVector(destination, f.byteWidth, defined, f.legacy)
	return true, true
}

func x86CallerPackedFloatShuffleStep(ins *Instr, f x86PackedFloatShuffleForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if !x86ResultNamedPredicateInstruction(*ins) || f.mask >= 0 && !state.masks[ins.Args[f.mask].Reg] {
		return false
	}
	var first uint64
	if f.memory >= 0 {
		// A caller slice has no legacy m128 alignment promise. A mask or
		// selector never reduces the separately checked full native tuple.
		if f.legacy || !x86CallerOrdinaryMemoryStep(ins, f.memory, state, proof, int64(f.memoryBytes), false) {
			return false
		}
		first = x86CallerVectorByteMask(int64(f.memoryBytes))
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[f.first].Reg)]
	}
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	old := state.vectors[destination]
	defined := f.definedBytes(first, state.vectors[x86CallerVectorRoot(ins.Args[f.second].Reg)], old)
	upper := ^x86CallerVectorByteMask(int64(f.byteWidth))
	if f.legacy {
		upper &= old
	}
	state.vectors[destination] = upper | defined
	return true
}
