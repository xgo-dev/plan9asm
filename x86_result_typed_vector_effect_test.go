package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86ResultTypedVectorEffectUnifiedSemantics(t *testing.T) {
	t.Run("PackedBinaryLaneAndUpperWrite", func(t *testing.T) {
		// Legacy PMULLW preserves upper ZMM bytes and propagates per 16-bit lane in standalone mode,
		// while strictWordMultiply requires all 16 bytes of both sources.
		legacy := x86ScalarLaneInstruction(t, "PMULLW X0,X1")
		state := x86ResultState{}
		state.writeVector(0, 64, 0x00ff, false)
		state.writeVector(1, 64, 0xa5a500000000ffff, false)
		laneState := state.clone()
		if accepted, known := x86ResultTypedVectorEffectStep(legacy, &laneState, nil, "amd64", false, false); !known || !accepted {
			t.Fatal("standalone PMULLW per-lane transfer failed")
		}
		if got, want := laneState.vectorBytes(1), uint64(0xa5a50000000000ff); got != want {
			t.Fatalf("legacy PMULLW per-lane = %#x, want %#x (upper preserved)", got, want)
		}
		strictState := state.clone()
		if accepted, known := x86ResultTypedVectorEffectStep(legacy, &strictState, nil, "amd64", false, true); !known || accepted || !reflect.DeepEqual(strictState, state) {
			t.Fatal("strict PMULLW accepted partial vector input or mutated state")
		}

		// EVEX VPADDD with merging mask clears upper ZMM bytes and preserves only lanes defined in sources & old dest.
		evex := x86ScalarLaneInstruction(t, "VPADDD X0,X1,K1,X2")
		mState := x86ResultState{masks: [8]bool{1: true}}
		mState.writeVector(0, 64, 0x0fff, false)             // lanes 0,1,2 known; lane 3 partial
		mState.writeVector(1, 64, 0xffff, false)             // all lanes known
		mState.writeVector(2, 64, 0xffff0000000000ff, false) // upper known; low lanes 0,1 known
		if accepted, known := x86ResultTypedVectorEffectStep(evex, &mState, nil, "amd64", false, false); !known || !accepted {
			t.Fatal("EVEX merging VPADDD failed")
		}
		// Upper 48 bytes cleared by EVEX (all 1s above byte 15), low 16 bytes = lanes 0,1 only (0x00ff).
		if got, want := mState.vectorBytes(2), uint64(0xffffffffffff00ff); got != want {
			t.Fatalf("EVEX merging VPADDD = %#x, want %#x", got, want)
		}
	})

	t.Run("IFMASevenByteSourcesEightByteAccumulatorAndBroadcast", func(t *testing.T) {
		ins := x86ScalarLaneInstruction(t, "VPMADD52LUQ.Z X0,X1,K1,X2")
		state := x86ResultState{masks: [8]bool{1: true}}
		// Missing byte 7 in both multiplicands must NOT poison lane 0 (52-bit inputs use low 7 bytes).
		state.writeVector(0, 64, 0x7f7f, false)
		state.writeVector(1, 64, 0x7f7f, false)
		// Missing byte 15 in old accumulator MUST poison lane 1 even under .Z.
		state.writeVector(2, 64, 0x7fff, false)
		if accepted, known := x86ResultTypedVectorEffectStep(ins, &state, nil, "amd64", false, false); !known || !accepted {
			t.Fatal("IFMA transfer failed")
		}
		if got, want := state.vectorBytes(2), uint64(0xffffffffffff00ff); got != want {
			t.Fatalf("IFMA defined bytes = %#x, want %#x", got, want)
		}

		// Broadcast memory form rejects standalone (nativeRead=false) without mutating state,
		// and succeeds under paired lowering (nativeRead=true) with valid pointer GP.
		bcst := x86ScalarLaneInstruction(t, "VPMADD52HUQ.BCST (SI),Y1,Y2")
		bState := x86ResultState{}
		bState.pointerGP[6] = true
		bState.writeVector(1, 64, 0x7f7f7f7f, false)
		bState.writeVector(2, 64, 0xffffffff, false)
		before := bState.clone()
		if accepted, known := x86ResultTypedVectorEffectStep(bcst, &bState, nil, "amd64", false, false); !known || accepted || !reflect.DeepEqual(bState, before) {
			t.Fatal("standalone IFMA.BCST accepted native memory or mutated state")
		}
		if accepted, known := x86ResultTypedVectorEffectStep(bcst, &bState, nil, "amd64", true, true); !known || !accepted {
			t.Fatal("paired IFMA.BCST rejected initialized pointer and 7-byte sources")
		}
		if got, want := bState.vectorBytes(2), ^uint64(0); got != want {
			t.Fatalf("paired IFMA.BCST defined bytes = %#x, want %#x", got, want)
		}
	})

	t.Run("TernaryLogicTruthTableAndMandatoryMemory", func(t *testing.T) {
		// Constant selector $0xFF ignores all 3 register inputs, so uninitialized registers still define full destination.
		constIns := x86ScalarLaneInstruction(t, "VPTERNLOGD $255,X0,X1,X2")
		cState := x86ResultState{}
		if accepted, known := x86ResultTypedVectorEffectStep(constIns, &cState, nil, "amd64", false, false); !known || !accepted {
			t.Fatal("constant VPTERNLOGD failed")
		}
		if got, want := cState.vectorBytes(2), ^uint64(0); got != want {
			t.Fatalf("constant VPTERNLOGD defined bytes = %#x, want %#x", got, want)
		}

		// Constant selector with memory operand STILL requires valid address (cannot waive memory fault).
		memIns := x86ScalarLaneInstruction(t, "VPTERNLOGD $0,(AX),X1,X2")
		mState := x86ResultState{}
		before := mState.clone()
		if accepted, known := x86ResultTypedVectorEffectStep(memIns, &mState, nil, "amd64", true, true); !known || accepted || !reflect.DeepEqual(mState, before) {
			t.Fatal("VPTERNLOGD with unknown memory address accepted or mutated state")
		}
	})

	t.Run("FMA3ScalarPreservedBytesAndZeroMaskAccumulator", func(t *testing.T) {
		ins := x86ScalarLaneInstruction(t, "VFMADD213SD.Z X0,X1,K1,X2")
		state := x86ResultState{masks: [8]bool{1: true}}
		state.writeVector(0, 64, 0x00ff, false)
		state.writeVector(1, 64, 0x00ff, false)
		// Only low 8 bytes + byte 9 of X2 are known; upper XMM bytes 8..15 preserve old knownness, bits 16..63 zeroed.
		state.writeVector(2, 64, 0x02ff, false)
		if accepted, known := x86ResultTypedVectorEffectStep(ins, &state, nil, "amd64", false, false); !known || !accepted {
			t.Fatal("scalar FMA3 failed")
		}
		if got, want := state.vectorBytes(2), uint64(0xffffffffffff02ff); got != want {
			t.Fatalf("scalar FMA3 defined bytes = %#x, want %#x", got, want)
		}

		// Missing low byte of destination must fail even under .Z.
		missingDest := x86ResultState{masks: [8]bool{1: true}}
		missingDest.writeVector(0, 64, 0x00ff, false)
		missingDest.writeVector(1, 64, 0x00ff, false)
		missingDest.writeVector(2, 64, 0x007f, false)
		before := missingDest.clone()
		if accepted, known := x86ResultTypedVectorEffectStep(ins, &missingDest, nil, "amd64", false, false); !known || accepted || !reflect.DeepEqual(missingDest, before) {
			t.Fatal("scalar FMA3.Z accepted partial destination or mutated state")
		}
	})

	t.Run("TypedEffectEquivalenceWithFixedLocalConsumer", func(t *testing.T) {
		for _, text := range []string{
			"VPMADD52LUQ X0,X1,X2",
			"VPTERNLOGD $150,X0,X1,X2",
			"VFMADD213PD X0,X1,X2",
			"VPMINSD X0,X1,X2",
			"VPCONFLICTD X0,X1",
			"PMULLW X0,X1",
			"PMULLD X0,X1",
			"PMULDQ X0,X1",
		} {
			ins := x86ScalarLaneInstruction(t, text)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil {
				t.Fatalf("x86TypedInstructionByteEffect(%q) failed: known=%v err=%v", text, known, err)
			}
			if len(effect.operands) == 0 {
				t.Fatalf("x86TypedInstructionByteEffect(%q) returned no operands", text)
			}
		}
		for _, text := range []string{
			"VPADDD X0,X1,X2",
			"VPMULLD Y0,Y1,Y2",
		} {
			ins := x86ScalarLaneInstruction(t, text)
			parsed, known, err := x86PackedArithmeticProperties(ins.Op, ins, "amd64", x86PackedArithmeticAdd|x86PackedArithmeticLowMultiply)
			if !known || err != nil {
				t.Fatalf("x86PackedArithmeticProperties(%q) failed: known=%v err=%v", text, known, err)
			}
			effect := x86PackedBinaryLaneEffect(ins, parsed.x86PackedBinaryForm, uint8(parsed.spec.laneBits/8))
			if effect.vectorLaneBytes != 4 || effect.vector.upperWrite != x86TypedVectorUpperZero || len(effect.operands) != 3 {
				t.Fatalf("x86PackedBinaryLaneEffect(%q) = %+v, unexpected lane/upper/operands", text, effect)
			}
		}
	})
}
