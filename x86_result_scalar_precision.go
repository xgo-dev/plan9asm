package plan9asm

// The complete physical mode and generation are captured at raw decoding.
// Zero is absent, not an assertion of legacy/VEX or a reusable source proof.
type x86RawScalarPrecisionIdentity struct {
	arch          string
	encoded, evex bool
}

func x86ScalarPrecisionRawIdentity(ins Instr, arch string) x86RawScalarPrecisionIdentity {
	if _, known, err := x86ScalarPrecisionProperties(ins.Op, ins, arch); !known || err != nil {
		return x86RawScalarPrecisionIdentity{}
	}
	return x86RawScalarPrecisionIdentity{arch, ins.x86Encoded, ins.x86ScalarPrecisionEVEX}
}

func x86RawScalarPrecisionSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && ins.x86Encoded && origin.scalarPrecision.arch == arch &&
		origin.scalarPrecision == x86ScalarPrecisionRawIdentity(ins, arch) &&
		x86RawOrdinaryVectorSource(ins, arch)
}

// Read the sealed decoded inventory before any named/strict fast path. Removing
// both mutable origin fields cannot launder a physical conversion into named
// source, or hide an edited producer elsewhere in its complete function.
func x86ScalarPrecisionRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if _, known, _ := x86ScalarPrecisionProperties(ins.Op, ins, arch); known {
			return true
		}
	}
	return false
}

// Active floating input and possible merge bytes are mandatory, including
// Void: implementation zeros cannot stand in for their native exceptions.
// Independently copied upper bytes may stay unknown and supply no pointer,
// backing, frame, caller or raw-entry fact.
func x86ResultScalarPrecisionStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86ScalarPrecisionProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawScalarPrecisionSource(ins, arch) {
			return false, true
		}
		// Only this bound source's original native opcode owns the conditional
		// numerical read. No subsequent access gains a pointer/backing fact.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	input := int64(form.spec.inputBits / 8)
	if form.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[0], input, state, owned, arch, native) {
			return false, true
		}
	} else {
		source, _ := amd64ParseXReg(ins.Args[0].Reg)
		required := x86CallerVectorByteMask(input)
		if state.vectorBytes(source)&required != required {
			return false, true
		}
	}
	destination, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
	output := x86CallerVectorByteMask(int64(form.spec.outputBits / 8))
	if form.mask >= 0 && !form.zeroing && state.vectorBytes(destination)&output != output {
		return false, true
	}
	base, _ := amd64ParseXReg(ins.Args[form.second].Reg)
	defined := output | state.vectorBytes(base)&(0xffff&^output)
	state.writeVector(destination, 16, defined, form.legacy)
	return true, true
}
