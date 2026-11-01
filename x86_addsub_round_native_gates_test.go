package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestX86AlternatingRoundNativeContinuationBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			text            string
			vex, pairedRead bool
			tuple, carrier  int
		}{
			{"ADDSUBPS (AX),X1", false, true, 16, 16},
			{"VADDSUBPS (AX),Y1,Y2", true, true, 32, 32},
			{"ROUNDPS $7,(AX),X2", false, true, 16, 16},
			{"VROUNDPS $7,(AX),Y2", true, true, 32, 32},
			{"ROUNDSS $7,(AX),X2", false, true, 4, 16},
			{"VROUNDSS $7,(AX),X1,X2", true, true, 4, 16},
			{"ROUNDSD $7,(AX),X2", false, true, 8, 16},
			{"VROUNDSD $7,(AX),X1,X2", true, true, 8, 16},
		} {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				if arch == "386" && (ins.Op == "VROUNDSS" || ins.Op == "VROUNDSD") {
					if _, known, err := x86RoundProperties(ins, arch); !known || err == nil {
						t.Fatal("ordinary mode32 scalar four-operand source lost its Go refusal")
					}
					return // A source rejection is not a tested native-memory continuation.
				}
				round := strings.Contains(row.text, "ROUND")
				memory, destination := 0, 1
				if round {
					memory, destination = 1, len(ins.Args)-1
				} else if row.vex {
					destination = 2
				}
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.pointerGP[0] = true
				// Partial high aliases distinguish legacy preservation from VEX zeroing.
				state.writeVector(1, 64, 0xffffffff, false)
				state.writeVector(2, 64, 0xffffffffffff, false)
				apply := func(i Instr, s *x86ResultState, native bool) (bool, bool) {
					if round {
						return x86ResultRoundStep(i, s, nil, arch, native)
					}
					return x86ResultAlternatingFloatStep(i, s, nil, arch, native)
				}
				for _, change := range []string{"paired", "unpaired", "numeric-base", "missing-index", "raw", "address-size", "segment", "missing-upper"} {
					current, changed := state.clone(), ins
					changed.Args = append([]Operand(nil), ins.Args...)
					native := true
					switch change {
					case "unpaired":
						native = false
					case "numeric-base":
						current.pointerGP[0] = false
						current.gp[0] = 0xff
					case "missing-index":
						changed.Args[memory].Mem.Index, changed.Args[memory].Mem.Scale = DX, 2
					case "raw":
						changed.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: ins.Args}
					case "address-size":
						changed.x86AddressBits = 16
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "missing-upper":
						current.writeVector(1, 64, 0, false)
						current.writeVector(2, 64, 0, false)
					}
					before := current.clone()
					accepted, known := apply(changed, &current, native)
					// Encoding selects operand roles and upper aliases. Paired read
					// permission is independent: legacy memory now has a whole SSE
					// emitter too. Scalar ROUND propagates only available upper bytes.
					want := row.pairedRead && (change == "paired" || change == "missing-upper" && round ||
						change == "raw" && row.vex && !round)
					if change == "raw" && row.vex && !round {
						// This primitive checks exact instruction metadata, not the
						// original whole producer. Its caller must check replay first.
						fake := Func{Sym: "fake", Instrs: []Instr{changed}}
						if err := x86LoweredNumericalProducerReplay(fake, arch); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("fabricated raw primitive acquired whole-source replay", err)
						}
					}
					if !known || accepted != want {
						t.Fatal("paired source contract or encoding role changed", change, known, accepted, want)
					}
					if !accepted {
						if !reflect.DeepEqual(before, current) {
							t.Fatal("rejected result changed source state", change)
						}
						continue
					}
					expected := before.clone()
					index, _ := amd64VectorRegisterIndex(ins.Args[destination].Reg, row.carrier)
					defined := x86CallerVectorByteMask(int64(row.carrier))
					if change == "missing-upper" && round && (strings.HasSuffix(string(ins.Op), "SS") || strings.HasSuffix(string(ins.Op), "SD")) {
						defined = x86CallerVectorByteMask(int64(row.tuple))
					}
					expected.writeVector(index, row.carrier, defined, !row.vex)
					if !reflect.DeepEqual(current, expected) {
						t.Fatal("native read changed pointer, FLAGS, unrelated bytes or storage", change)
					}
					if x86ResultRead(changed.Args[memory], int64(row.tuple), &current, nil, arch) {
						t.Fatal("paired read granted later numerical storage", change)
					}
				}
			})
		}
	}
}

func TestX86AlternatingRoundGrammarIsNotModeOrNativeAuthority(t *testing.T) {
	// Existing VEX ADDSUB grammar accepts Go's high X/Y class in mode32;
	// numerical transfer independently refuses an inaccessible physical bank.
	ins := x86ScalarLaneInstruction(t, "VADDSUBPS (AX),Y14,Y15")
	form, known, err := x86AlternatingFloatProperties(ins, "386")
	if !known || err != nil || form.byteWidth != 32 || form.memoryBytes != 32 {
		t.Fatal("original VEX grammar or tuple changed", known, err)
	}
	state := x86ResultState{}
	state.pointerGP[0] = true
	state.writeVector(14, 64, ^uint64(0), false)
	before := state.clone()
	if accepted, known := x86ResultAlternatingFloatStep(ins, &state, nil, "386", true); !known || accepted || !reflect.DeepEqual(before, state) {
		t.Fatal("grammar authorized a mode32 high physical register")
	}
	for _, text := range []string{"VROUNDSS $7,(R8),X1,X2", "VADDSUBPS (R8),Y1,Y2"} {
		ins := x86ScalarLaneInstruction(t, text)
		state := x86ResultState{}
		state.pointerGP[8] = true
		state.writeVector(1, 64, ^uint64(0), false)
		before := state.clone()
		var accepted, known bool
		if strings.Contains(text, "ROUND") {
			accepted, known = x86ResultRoundStep(ins, &state, nil, "386", true)
		} else {
			accepted, known = x86ResultAlternatingFloatStep(ins, &state, nil, "386", true)
		}
		if !known || accepted || !reflect.DeepEqual(before, state) {
			t.Fatal("memory syntax granted a mode32 R8 pointer", text)
		}
	}
	for _, text := range []string{"VROUNDSS $7,(AX),X8,X2", "VROUNDPD $7,(AX),Y8"} {
		if _, known, err := x86RoundProperties(x86ScalarLaneInstruction(t, text), "386"); !known || err == nil {
			t.Fatal("ROUND original mode32 carrier restriction changed", text)
		}
	}
	for _, row := range []struct {
		text  string
		tuple int64
	}{
		{"VROUNDSS $7,(AX),X1,X2", 4},
		{"VROUNDSD $7,(AX),X1,X2", 8},
		{"VROUNDPD $7,(AX),Y2", 32},
	} {
		ins := x86ScalarLaneInstruction(t, row.text)
		// Physical tuple/effect inspection only, not ordinary source or NUM authority.
		ins.x86Encoded = true
		form, known, err := x86RoundProperties(ins, "386")
		effect, effectKnown, effectErr := x86TypedRoundByteEffect(ins.Op, ins, "386")
		if !known || err != nil || !effectKnown || effectErr != nil || int64(form.memoryBytes) != row.tuple || effect.operands[1].width != row.tuple || !effect.requiresResultProof {
			t.Fatal("scalar native tuple became a vector carrier or lost its source proof", row.text)
		}
		if form.spec.scalar && (len(effect.operands) != 4 || !effect.operands[2].read || effect.operands[2].requiredBytes != (0xffff&^x86CallerVectorByteMask(row.tuple))) {
			t.Fatal("scalar upper-copy bytes lost their independent typed source obligation", row.text)
		}
	}
	for _, text := range []string{"ADDSUBPS X0,X1", "ADDSUBPD X0,X1", "ROUNDPS $7,X0,X1", "ROUNDPD $7,X0,X1", "ROUNDSS $7,X0,X1", "ROUNDSD $7,X0,X1"} {
		ins := x86ScalarLaneInstruction(t, text)
		for _, native := range []bool{false, true} {
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.writeVector(0, 64, ^uint64(0), false)
			state.writeVector(1, 64, ^uint64(0), false)
			before := state.clone()
			var accepted, known bool
			if strings.Contains(text, "ROUND") {
				accepted, known = x86ResultRoundStep(ins, &state, nil, "386", native)
			} else {
				accepted, known = x86ResultAlternatingFloatStep(ins, &state, nil, "386", native)
			}
			if !known || !accepted || !reflect.DeepEqual(before, state) {
				t.Fatal("fully defined legacy registers depended on native read permission or lost aliases", text, native)
			}
		}
	}
}
