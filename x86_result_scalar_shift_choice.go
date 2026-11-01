package plan9asm

import (
	"fmt"
	"reflect"
)

// The standalone steps cannot distinguish a legacy decoded instruction whose
// origin was erased from an otherwise identical named instruction. These
// producer families therefore check the immutable complete source once before
// their paired proof. Inspect current and sealed decoded instructions so an
// erased origin or edited opcode cannot erase that restriction. This is never
// an input, caller, native-entry or memory-backing permission.
func x86LoweredNumericalProducerReplay(fn Func, arch string) error {
	hasProducer := func(instructions []Instr) bool {
		for _, ins := range instructions {
			if ins.x86SourceRaw == nil {
				continue
			}
			if ins.x86SourceRaw.scalarSegmentLoad.arch != "" {
				return true // A physical segment read cannot outlive its complete sealed source.
			}
			if _, known := amd64MaskMoveSpecs[ins.Op]; known {
				return true // Exact raw KMOV access cannot survive erased or edited producer identity.
			}
			if form, known, _ := x86ScalarShiftProperties(ins.Op, ins, arch); known && !form.bmi2 {
				return true
			}
			if form, known, _ := x86FloatCompareProperties(ins, arch); known && form.legacy {
				return true
			}
			if _, known, _ := x86BlendMinposProperties(ins.Op, ins, arch); known {
				return true
			}
			if _, known, _ := x86ImmediateBlendProperties(ins.Op, ins, arch); known {
				return true
			}
			if form, known, _ := x86AlternatingFloatProperties(ins, arch); known && !form.legacy {
				return true // Erased or edited raw arithmetic origins cannot skip whole-source replay.
			}
			if _, known, _ := x86MULXProperties(ins.Op, ins, arch); known {
				return true
			}
			if _, known, _ := x86ElementPermuteProperties(ins.Op, ins, arch); known {
				return true
			}
			if _, known, _ := x86PackedSignExtendProperties(ins, arch); known {
				return true // Restrict erased raw origins; this does not grant a raw SX result role.
			}
			if _, known, _ := x86PackedFloatShuffleProperties(ins.Op, ins, arch); known {
				return true
			}
			if _, known, _ := x86ScalarFloatIntegerProperties(ins, arch); known {
				return true // Restrict erased raw origins before ordinary strict success.
			}
			if form, known, _ := x86IntegerMinMaxProperties(ins.Op, ins, arch); known && form.legacy {
				return true
			}
		}
		return false
	}
	replay := fn.x86RawReplay
	if !x86FMA3RawReplayRequired(fn, arch) && !x86NamedHalfRawReplayRequired(fn, arch) &&
		!hasProducer(fn.Instrs) && (replay == nil || !hasProducer(replay.decoded)) {
		return nil // Ordinary named source keeps its existing input/unknown domain.
	}
	if replay == nil {
		return fmt.Errorf("%w: lowering producer needs its original whole-source replay", ErrProbeNeedsContext)
	}
	return replay.validate(fn, arch)
}

func x86RawLegacyScalarShiftSource(ins Instr, arch string) bool {
	form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && !form.bmi2 && origin != nil && origin.op == ins.Op &&
		reflect.DeepEqual(origin.args, ins.Args) && origin.vectorBytes == ins.x86VectorBytes &&
		ins.x86RawNearReturn == nil && ins.x86AddressBits == 0 && !ins.x86UnboundAddressOverride &&
		ins.x86SegmentPrefix == 0 && !ins.x86RIPLiteral && ins.x86NumericalRead == nil
}

// The paired scalar emitter materializes only producer-specific ISA choices.
// It grants neither public-query definedness nor native FLAGS, entry, caller,
// frame or memory-backing authority. Native RMW retains its exact volatile load
// and store, including zero count and otherwise unobservable chosen outputs.
func x86LoweredScalarShiftChoiceStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
	if !known || form.bmi2 {
		return false, false
	}
	if err != nil {
		return false, true
	}
	local := ins
	if !x86ResultNamedPredicateInstruction(local) {
		if !x86RawLegacyScalarShiftSource(ins, arch) {
			return false, true
		}
		local.x86Encoded, local.x86SourceRaw = false, nil
	}
	next := state.clone()
	next.loweredStaticReads = state.loweredStaticReads
	if x86LoweredScalarShiftTransfer(local, form, &next, owned, resultOffset, arch) {
		*state = next
		return true, true
	}
	// Retain only the already closed nontrapping GP fallback. It does not
	// materialize choices or initialize missing dependent bytes/FLAGS. Memory
	// accesses and W-double forms outside that old domain cannot borrow it.
	return x86LoweredPureGPUnknownTransfer(local, state, arch), true
}
