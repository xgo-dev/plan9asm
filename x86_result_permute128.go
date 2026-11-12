package plan9asm

type x86RawPermute128Identity struct {
	arch    string
	vex     bool
	encoded bool
}

func x86Permute128RawIdentity(ins Instr, arch string) x86RawPermute128Identity {
	if _, known, err := x86Permute128Properties(ins.Op, ins, arch); !known || err != nil ||
		!ins.x86Permute128VEX || !ins.x86Encoded || ins.x86VectorBytes != 32 {
		return x86RawPermute128Identity{}
	}
	return x86RawPermute128Identity{arch, true, true}
}

func x86RawPermute128Source(ins Instr, arch string) bool {
	form, known, err := x86Permute128Properties(ins.Op, ins, arch)
	return known && err == nil && ins.x86SourceRaw != nil &&
		ins.x86SourceRaw.permute128.arch == arch &&
		ins.x86SourceRaw.permute128 == x86Permute128RawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSourceAt(ins, arch, form.first)
}

func x86Permute128RawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay != nil {
		for _, ins := range fn.x86RawReplay.decoded {
			if _, known, _ := x86Permute128Properties(ins.Op, ins, arch); known {
				return true
			}
		}
	}
	return false
}

// A raw operand gets only a lowering-local projection after exact identity
// checks. The form was captured before projection, so it cannot borrow Go's
// named mode32 arity or authorize a standalone/frame/caller/native entry.
func x86ResultPermute128Step(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86Permute128Properties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawPermute128Source(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	} else if ins.x86Permute128VEX {
		return false, true // A named source cannot fabricate physical generation.
	}
	var first uint64
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[form.first], 32, state, owned, arch, native) {
			return false, true
		}
		first = 0xffffffff // No reusable memory or address fact follows.
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[form.first].Reg, 32)
		first = state.vectorBytes(index)
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[form.second].Reg, 32)
	if !form.inputsDefined(first, state.vectorBytes(second)) {
		return false, true
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, 32)
	state.writeVector(destination, 32, 0xffffffff, false)
	return true, true
}

func x86CallerPermute128Step(ins *Instr, form x86Permute128Form, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if !x86ResultNamedPredicateInstruction(*ins) || ins.x86Permute128VEX {
		return false
	}
	first := uint64(0xffffffff)
	if form.memory >= 0 {
		if !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, 32, false) {
			return false
		}
	} else {
		first = state.vectors[x86CallerVectorRoot(ins.Args[form.first].Reg)]
	}
	second := state.vectors[x86CallerVectorRoot(ins.Args[form.second].Reg)]
	if !form.inputsDefined(first, second) {
		return false
	}
	state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)] = ^uint64(0)
	return true
}
