package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

// These unit fixtures describe independently owned logical bytes only. They
// carry no original instruction, native pointer, caller or entry authority.
func x86X87IntegerStateFixture() (x86ResultState, []bool) {
	state := x86ResultState{
		fp: make([]bool, 32),
		x87: &x86ResultX87State{word: &x86ResultX87WordState{
			layout: &x86X87WordLayout{parameters: map[int64]bool{0: true}},
		}},
		flags:     x86ByteFlagsAll,
		direction: x86ResultDirectionForward,
	}
	owned := make([]bool, len(state.fp))
	for offset := range owned {
		owned[offset] = true
		state.fp[offset] = offset < 16
	}
	return state, owned
}

func x86X87IntegerStateStep(t *testing.T, state *x86ResultState, owned []bool, arch, source string) {
	t.Helper()
	if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, source), state, owned, 16, arch); !known || !accepted {
		t.Fatal("independent typed x87 state transfer rejected", arch, source, known, accepted)
	}
}

func TestX86X87IntegerSourceFactsFollowExactCells(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			width  uint8
		}{
			{"FMOVW input+0(FP),F0", 2},
			{"FMOVL input+0(FP),F0", 4},
			{"FMOVV input+0(FP),F0", 8},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				state, owned := x86X87IntegerStateFixture()
				step := func(source string) { x86X87IntegerStateStep(t, &state, owned, arch, source) }
				step(row.source)
				if state.x87.depth != 1 || state.x87.integer != [8]uint8{row.width} {
					t.Fatal("integer load did not push exactly its source signed bound", *state.x87)
				}
				step("FMOVD F0,F0") // Go's first matching row reads old F0, then pushes it.
				if state.x87.depth != 2 || state.x87.integer != [8]uint8{row.width, row.width} {
					t.Fatal("register FLD lost its read-before-push source identity", *state.x87)
				}
				step("FLD1")
				step("FMOVD F1,F0")
				if state.x87.integer != [8]uint8{row.width, 0, row.width, row.width} {
					t.Fatal("register FLD read the shifted rather than original source cell", *state.x87)
				}
				step("FXCHD F0,F1")
				if state.x87.integer != [8]uint8{0, row.width, row.width, row.width} {
					t.Fatal("FXCH changed unrelated cells or manufactured an integer bound", *state.x87)
				}
				step("FMOVD F0,F2")
				if state.x87.integer != [8]uint8{0, row.width, 0, row.width} {
					t.Fatal("non-pop register copy retained a stale overwritten-cell bound", *state.x87)
				}
				step("FMOVDP F0,F1")
				if state.x87.depth != 3 || state.x87.integer != [8]uint8{0, 0, row.width} {
					t.Fatal("pop copy did not write before shifting exact cells", *state.x87)
				}
				if state.flags != x86ByteFlagsAll || state.direction != x86ResultDirectionForward {
					t.Fatal("value-availability transfers changed integer FLAGS or DF")
				}
			})
		}
		for _, source := range []string{"FABS", "FCHS", "FSQRT", "FADDD F0,F1", "FADDDP F0,F1"} {
			t.Run(arch+"/revoke/"+source, func(t *testing.T) {
				state, owned := x86X87IntegerStateFixture()
				state.x87.slots, state.x87.depth = 7, 3
				state.x87.integer = [8]uint8{2, 4, 8}
				x86X87IntegerStateStep(t, &state, owned, arch, source)
				want := [8]uint8{0, 4, 8}
				if source == "FADDD F0,F1" {
					want = [8]uint8{2, 0, 8}
				} else if source == "FADDDP F0,F1" {
					want = [8]uint8{0, 8}
				}
				if state.x87.integer != want {
					t.Fatal("arithmetic/unary effect did not revoke only its actual written cell", source, state.x87.integer, want)
				}
			})
		}
		t.Run(arch+"/float-memory-roundtrip", func(t *testing.T) {
			state, owned := x86X87IntegerStateFixture()
			x86X87IntegerStateStep(t, &state, owned, arch, "FMOVV input+0(FP),F0")
			x86X87IntegerStateStep(t, &state, owned, arch, "FMOVDP F0,output+16(FP)")
			x86X87IntegerStateStep(t, &state, owned, arch, "FMOVD output+16(FP),F0")
			if state.x87.depth != 1 || state.x87.integer != [8]uint8{} {
				t.Fatal("double-memory roundtrip inherited an exact I64 source fact", *state.x87)
			}
		})
		for _, source := range []string{"FMOVD F1,F0", "FMOVDP F0,F1", "FXCHD F0,F1", "FADDDP F0,F1"} {
			t.Run(arch+"/read-before-write/"+source, func(t *testing.T) {
				state, owned := x86X87IntegerStateFixture()
				state.x87.slots, state.x87.depth = 1, 1
				state.x87.integer[0] = 8
				// A destination F1 may be created by a store/copy, but every
				// actual input must exist before a push, pop or overwrite.
				if source == "FMOVDP F0,F1" {
					state.x87.slots = 0
				}
				if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, source), &state, owned, 16, arch); !known || accepted {
					t.Fatal("an output/push supplied its own missing input", source, known, accepted)
				}
			})
		}
	}
}

func TestX86X87IntegerSourceFactCloneJoinAndRevoke(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, first := range []uint8{0, 2, 4, 8} {
			for _, last := range []uint8{0, 2, 4, 8} {
				t.Run(fmt.Sprintf("%s/join/%d/%d", arch, first, last), func(t *testing.T) {
					state, _ := x86X87IntegerStateFixture()
					state.x87.slots, state.x87.depth = 3, 2
					state.x87.integer = [8]uint8{first, 2}
					other := state.clone()
					other.x87.integer[0] = last
					if state.x87.integer[0] != first || other.x87.word == state.x87.word {
						t.Fatal("CFG clone shared mutable integer/control state")
					}
					want := first
					if first == 0 || last == 0 {
						want = 0
					} else if last > want {
						want = last // Both paths fit the common wider signed range.
					}
					for _, joined := range []x86ResultState{state.intersect(other), other.intersect(state)} {
						if joined.x87.invalid || joined.x87.integer != [8]uint8{want, 2} {
							t.Fatal("join invented a narrower or one-sided signed bound", joined.x87)
						}
					}
					other.x87.slots &^= 1
					if joined := state.intersect(other); joined.x87.integer[0] != 0 {
						t.Fatal("unavailable joined cell retained a signed source fact")
					}
				})
			}
		}
		for _, axis := range []string{"different-depth", "foreign-layout", "unknown-shape", "missing-domain", "CALL", "FINIT"} {
			t.Run(arch+"/"+axis, func(t *testing.T) {
				state, owned := x86X87IntegerStateFixture()
				state.x87.slots, state.x87.depth = 3, 2
				state.x87.integer = [8]uint8{2, 8}
				layout := state.x87.word.layout
				other := state.clone()
				switch axis {
				case "different-depth":
					other.x87.depth++
					state = state.intersect(other)
				case "foreign-layout":
					other.x87.word.layout = &x86X87WordLayout{parameters: map[int64]bool{0: true}}
					state = state.intersect(other)
				case "unknown-shape":
					other.x87.revoke()
					state = state.intersect(other)
				case "missing-domain":
					other.x87 = nil
					state = state.intersect(other)
				case "CALL":
					x86ResultX87After(Instr{Op: OpCALL}, &state, arch)
				case "FINIT":
					x86X87IntegerStateStep(t, &state, owned, arch, "FINIT")
				}
				if state.x87.integer != [8]uint8{} || state.x87.slots != 0 || state.x87.depth != 0 {
					t.Fatal("shape/control boundary retained a mutable integer fact", axis, *state.x87)
				}
				if axis == "FINIT" {
					if state.x87.invalid || state.x87.word.control != 0xffff || state.x87.read(Operand{Kind: OpReg, Reg: "F0"}) {
						t.Fatal("FINIT did not reset shape, or invented an F0 value")
					}
				} else if !state.x87.invalid {
					t.Fatal("unrelated/unknown states acquired a common known shape", axis)
				}
				if axis == "CALL" && (state.x87.word == nil || state.x87.word.layout != layout) {
					t.Fatal("CALL erased immutable actual layout rather than mutable facts")
				}
			})
		}
	}
	for _, shape := range []bool{false, true} {
		plan, state, owned := x86ABI0BoolCallDomainState(t)
		state.shapeOnly = shape
		state.x87 = &x86ResultX87State{slots: 3, depth: 2, integer: [8]uint8{2, 8}}
		for ordinal := range plan.calls {
			if accepted, known := x86ABI0BoolCallStep(ordinal, plan.function.Instrs[ordinal], &state, owned, 4, "386"); !known || !accepted {
				t.Fatal("existing independently closed typed CALL no longer accepted", shape, known, accepted)
			}
			if !state.x87.invalid || state.x87.integer != [8]uint8{} {
				t.Fatal("direct typed CALL retained integer facts without the outer post-transfer hook", shape)
			}
		}
	}
}

func TestX86X87IntegerRoundingKeepsModeAndWidthBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, sourceWidth := range []uint8{0, 2, 4, 8} {
			for _, row := range []struct {
				source   string
				width    uint8
				pop      uint8
				hardware bool
			}{
				{"FMOVW F0,output+16(FP)", 2, 0, false},
				{"FMOVWP F0,output+16(FP)", 2, 1, false},
				{"FMOVL F0,output+16(FP)", 4, 0, false},
				{"FMOVLP F0,output+16(FP)", 4, 1, false},
				{"FMOVVP F0,output+16(FP)", 8, 1, true},
				{"FRNDINT", 0, 0, true},
			} {
				for _, control := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/source%d/control%t/%s", arch, sourceWidth, control, row.source), func(t *testing.T) {
						state, owned := x86X87IntegerStateFixture()
						state.x87.slots, state.x87.depth = 1, 1
						state.x87.integer[0] = sourceWidth
						if control {
							state.x87.word.control = 0xffff
						}
						ins := x86X87ValueInstruction(t, row.source)
						infallible := row.width != 0 && sourceWidth != 0 && sourceWidth <= row.width
						strict := state.clone()
						if accepted, known := x86ResultX87ValueStep(ins, &strict, owned, 16, arch); !known || accepted != (control || infallible) {
							t.Fatal("standalone observer inferred ambient control or rejected an exact integer range", known, accepted)
						}
						for _, mode := range []X87Mode{X87Auto, X87Hardware, X87Software} {
							consumer := amd64Ctx{x87Mode: mode}
							next := state.clone()
							accepted, known := consumer.x87HardwareRoundingResultStep(ins, &next, owned, 16, arch)
							wantKnown := row.hardware && mode != X87Software
							if known != wantKnown || accepted != wantKnown {
								t.Fatal("paired adapter covered a software W/L store or lost its actual native operation", mode, known, accepted)
							}
							if wantKnown && (next.x87.depth != 1-row.pop || row.width == 0 && next.x87.integer[0] != sourceWidth) {
								t.Fatal("paired native step changed unrelated stack/integer state", mode, next.x87)
							}
							if mode != X87Software && row.hardware {
								next = state.clone()
								next.x87.slots = 0
								if accepted, known := consumer.x87HardwareRoundingResultStep(ins, &next, owned, 16, arch); !known || accepted {
									t.Fatal("ambient hardware control created a missing F0 value")
								}
							}
							if !row.hardware {
								next = state.clone()
								accepted, known := x86ResultX87ValueStepWithHardwareRounding(ins, &next, owned, 16, arch, true)
								if !known || accepted != (control || infallible) {
									t.Fatal("internal hardware flag leaked to a nonnative W/L emitter")
								}
							}
							if strict.flags != x86ByteFlagsAll || strict.direction != x86ResultDirectionForward {
								t.Fatal("rounding defined integer FLAGS or DF")
							}
						}
					})
				}
			}
		}
	}
}

func TestX86X87IntegerStoresReuseOnlyNaturalWordShadow(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			source string
			accept bool
		}{
			{"FMOVW F0,input+0(FP)", true},
			{"FMOVWP F0,input+0(FP)", true},
			{"FMOVW F0,input+1(FP)", false},
			{"FMOVW F0,input+2(FP)", false},
			{"FMOVL F0,input+0(FP)", false},
			{"FMOVLP F0,input+0(FP)", false},
			{"FMOVVP F0,input+0(FP)", false},
			{"FMOVW F0,(AX)", false},
		} {
			for _, inputKnown := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/defined%t/%s", arch, inputKnown, row.source), func(t *testing.T) {
					state, owned := x86X87IntegerStateFixture()
					state.x87.slots, state.x87.depth = 1, 1
					if !inputKnown {
						state.x87.slots = 0
					}
					state.x87.word.control = 0xffff
					for index := range state.fp {
						state.fp[index] = false
					}
					accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, row.source), &state, owned, 16, arch)
					if !known || accepted != (row.accept && inputKnown) {
						t.Fatal("integer store enlarged an independent parameter/native role", known, accepted)
					}
					for offset, initialized := range state.fp {
						if initialized != (accepted && offset < 2) {
							t.Fatal("natural word writer changed a byte outside its exact old slot", offset, initialized)
						}
					}
				})
			}
		}
	}
}

func TestX86X87IntegerSourceFactsStayPrivateAndBounded(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ typ, load, store string }{
			{"int16", "FMOVW", "FMOVWP"},
			{"int32", "FMOVL", "FMOVLP"},
			{"int64", "FMOVV", "FMOVVP"},
		} {
			t.Run(arch+"/private/"+row.typ, func(t *testing.T) {
				declaration := "func Value(input " + row.typ + ") " + row.typ
				_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
				body := fmt.Sprintf("%s input+0(FP),F0\n%s F0,ret+%d(FP)\nRET", row.load, row.store, sig.Frame.Results[0].Offset)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, body)
				// No CW probe or FINIT: source integer load/store of equal
				// width is infallible under any rounding mode. This is not a
				// certificate that the old double representation preserves I64.
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatal("integer source fact failed before the independent numerical observer", err)
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("private source integer effects widened the public declaration query", err)
				}
			})
		}
		t.Run(arch+"/eight-cells", func(t *testing.T) {
			state, owned := x86X87IntegerStateFixture()
			if len(state.x87.integer) != 8 {
				t.Fatal("source fact escaped the fixed existing eight-cell stack")
			}
			for index := 0; index < 8; index++ {
				x86X87IntegerStateStep(t, &state, owned, arch, "FMOVW input+0(FP),F0")
			}
			before := *state.x87
			if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, "FMOVW input+0(FP),F0"), &state, owned, 16, arch); !known || accepted {
				t.Fatal("ninth push manufactured an extra source cell", known, accepted)
			}
			if *state.x87 != before {
				t.Fatal("failed push changed existing signed-width facts")
			}
			for index := 0; index < 8; index++ {
				x86X87IntegerStateStep(t, &state, owned, arch, "FMOVWP F0,output+16(FP)")
			}
			if state.x87.integer != [8]uint8{} || state.x87.depth != 0 || state.x87.slots != 0 {
				t.Fatal("pop retained facts outside the actual remaining stack")
			}
		})
		t.Run(arch+"/shape-is-not-values", func(t *testing.T) {
			state, owned := x86X87IntegerStateFixture()
			state.shapeOnly = true
			x86X87IntegerStateStep(t, &state, owned, arch, "FMOVV input+0(FP),F0")
			x86X87IntegerStateStep(t, &state, owned, arch, "FRNDINT")
			if state.x87.integer != [8]uint8{} || state.x87.depth != 0 || state.x87.slots != 0 || state.x87.word.control != 0 {
				t.Fatal("dead-source shape pass created live values or ambient control")
			}
		})
	}
}
