package plan9asm

// Physical generation, grammar and mode are distinct observations. Absence
// cannot assert F16C/VEX, and ordinary named conversions are not raw FP16.
type x86RawNamedHalfIdentity struct {
	arch     string
	encoding x86RawNamedHalfEncoding
	encoded  bool
}

func x86NamedHalfRawIdentity(ins Instr, arch string) x86RawNamedHalfIdentity {
	_, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
	if !known || err != nil || ins.x86Encoded ||
		ins.x86NamedHalfEncoding != x86RawNamedHalfVEX && ins.x86NamedHalfEncoding != x86RawNamedHalfEVEX {
		return x86RawNamedHalfIdentity{}
	}
	return x86RawNamedHalfIdentity{arch, ins.x86NamedHalfEncoding, ins.x86Encoded}
}

func x86RawNamedHalfSource(ins Instr, arch string) bool {
	f, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
	identity := x86NamedHalfRawIdentity(ins, arch)
	if !known || err != nil || identity.encoding == x86RawNamedHalfAbsent || ins.x86SourceRaw == nil ||
		ins.x86SourceRaw.namedHalf != identity || !x86RawOrdinaryVectorSourceAt(ins, arch, f.source) {
		return false
	}
	return f.memory != f.destination || x86RawOrdinaryVectorSourceAt(ins, arch, f.destination)
}

func x86NamedHalfRawReplayRequired(fn Func, arch string) bool {
	hasProducer := func(instructions []Instr) bool {
		for _, ins := range instructions {
			if _, known, _ := x86NamedHalfProperties(ins.Op, ins, arch); known &&
				(ins.x86SourceRaw != nil || ins.x86NamedHalfEncoding != x86RawNamedHalfAbsent) {
				return true
			}
		}
		return false
	}
	return hasProducer(fn.Instrs) || fn.x86RawReplay != nil && hasProducer(fn.x86RawReplay.decoded)
}

// Only this family selects the shared input/carrier axes. A paired native
// write changes no logical pointee, later read, frame, caller or entry fact.
func x86ResultNamedHalfStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	f, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
	if !known || err != nil || f.undefinedOpcode() {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		if !native || !x86RawNamedHalfSource(ins, arch) {
			return false, true
		}
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	local := ins
	local.Args = ins.Args[f.source:]
	if f.memory != f.destination {
		return x86ResultPackedConversionInputs(local, f.conversion, state, owned, arch, native), true
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.sourceBytes)
	input := x86CallerVectorByteMask(int64(f.inputBytes))
	if state.vectorBytes(index)&input != input {
		return false, true
	}
	destination := ins.Args[f.destination]
	return native && x86OrdinaryNativeMemoryOperand(destination, arch) &&
		x86ResultIncomingPointerAddressIdentity(destination, state, arch), true
}
