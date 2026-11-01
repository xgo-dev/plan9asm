package plan9asm

import "reflect"

// An absent snapshot is not evidence for a legacy or VEX encoding. The decoder
// records the actual generation before any numerical or literal projection.
type x86RawFloatMinMaxIdentity struct {
	arch          string
	encoded, evex bool
}

func x86FloatMinMaxRawIdentity(ins Instr, arch string) x86RawFloatMinMaxIdentity {
	if _, known, err := x86FloatMinMaxProperties(ins, arch); !known || err != nil {
		return x86RawFloatMinMaxIdentity{}
	}
	return x86RawFloatMinMaxIdentity{arch, ins.x86Encoded, ins.x86FloatMinMaxEVEX}
}

func x86RawFloatMinMaxEncodingSource(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	return origin != nil && origin.floatMinMax.arch == arch &&
		origin.floatMinMax == x86FloatMinMaxRawIdentity(ins, arch) &&
		origin.op == ins.Op && (reflect.DeepEqual(origin.args, ins.Args) || x86RawLiteralSourceIdentity(ins, arch)) &&
		origin.vectorBytes == ins.x86VectorBytes && origin.addressBits == ins.x86AddressBits
}

func x86RawFloatMinMaxSource(ins Instr, arch string) bool {
	return x86RawFloatMinMaxEncodingSource(ins, arch) && x86RawOrdinaryVectorSource(ins, arch)
}

func x86FloatMinMaxPreservesSourceState(ins Instr, arch string) bool {
	return x86RawFloatMinMaxSource(ins, arch) ||
		x86RawFloatMinMaxEncodingSource(ins, arch) && x86RawBinaryFloatLiteralForm(ins, arch)
}

// Consult the sealed decoded inventory, not a mutable current origin pointer.
// Removing an origin must not turn a physical instruction into a named one.
func x86FloatMinMaxRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if _, known, _ := x86FloatMinMaxProperties(ins, arch); known {
			return true
		}
	}
	return false
}

func x86ResultFloatMinMaxStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	f, known, err := x86FloatMinMaxProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) && !x86RawBinaryFloatLiteralForm(ins, arch) {
		if !nativeRead || !x86RawFloatMinMaxSource(ins, arch) {
			return false, true
		}
		// Only the exact paired native opcode consumes this local read view.
		// Complete source replay is checked once by the lowering owner.
		ins.x86Encoded, ins.x86SourceRaw = false, nil
	}
	return x86ScalarFPFloatBinaryTransferWithRead(ins, f.x86FloatBinaryForm, state, owned, arch, nativeRead), true
}
