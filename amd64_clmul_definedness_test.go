package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86CLMULSelectedQwordResultBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, vector := range []bool{false, true} {
			if arch == "386" && vector {
				continue // Stock Go rejects the four-operand source form.
			}
			for _, immediate := range []int{0, 1, 16, 17, 238, 239, 254, 255} {
				name, tail := "PCLMULQDQ", "X0,X1"
				if vector {
					name, tail = "VPCLMULQDQ", "X0,X1,X2"
				}
				t.Run(fmt.Sprintf("%s/%s/%d", arch, name, immediate), func(t *testing.T) {
					row := fmt.Sprintf("%s $%d,%s", name, immediate, tail)
					goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
					ins := x86ScalarLaneInstruction(t, row)
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagZF}
					state.xmm[0] = uint16(255) << uint((immediate>>4&1)*8)
					state.xmm[1] = uint16(255) << uint((immediate&1)*8)
					if !x86ResultTransfer(ins, &state, nil, 0, arch) {
						t.Fatal("complete selected qwords lack their registered result effect")
					}
					destination := 1
					if vector {
						destination = 2
					}
					if state.xmm[destination] != 0xffff || state.flags != x86ByteFlagCF|x86ByteFlagZF {
						t.Fatal("carryless product did not define exactly the full X result while preserving flags")
					}
				})
			}
		}
	}
}

func TestX86CLMULMissingByteAndAliasEffects(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, legacy := range []bool{true, false} {
			if legacy && bank != "X" {
				continue
			}
			for immediate := 0; immediate < 256; immediate++ {
				row := fmt.Sprintf("PCLMULQDQ $%d,X0,X1", immediate)
				if !legacy {
					row = fmt.Sprintf("VPCLMULQDQ $%d,%s0,%s1,%s2", immediate, bank, bank, bank)
				}
				ins := x86ScalarLaneInstruction(t, row)
				form, known, err := x86CLMULProperties(ins.Op, ins, "amd64")
				if !known || err != nil {
					t.Fatal(err)
				}
				for missing := -1; missing < form.byteWidth; missing++ {
					for source := 0; source < 2; source++ {
						inputs := [2]uint64{^uint64(0), ^uint64(0)}
						if missing >= 0 {
							inputs[source] &^= uint64(1) << uint(missing)
						}
						state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": inputs[0], "Z1": inputs[1], "Z2": 1 << 60}}
						if !x86CallerVectorMoveKnown(ins) || !x86CallerVectorMoveStep(&ins, &state, nil) {
							t.Fatal("complete register effect is unregistered", row)
						}
						want := ^uint64(0)
						if missing >= 0 {
							selector := immediate & 1
							if source == 0 {
								selector = immediate >> 4 & 1
							}
							if missing%16/8 == selector {
								want &^= uint64(65535) << uint(missing/16*16)
							}
						}
						destination := Reg("Z2")
						if legacy {
							destination = "Z1"
						}
						if state.vectors[destination] != want {
							t.Fatalf("%s missing %d operand %d got %016x want %016x", row, missing, source, state.vectors[destination], want)
						}
						result := x86ResultState{}
						result.writeVector(0, 64, inputs[0], false)
						result.writeVector(1, 64, inputs[1], false)
						result.writeVector(2, 64, 1<<60, false)
						if !x86ResultTransfer(ins, &result, nil, 0, "amd64") {
							t.Fatal("partial known bytes lost the effect registration")
						}
						index := 2
						if legacy {
							index = 1
						}
						if result.vectorBytes(index) != want {
							t.Fatal("caller/result complete numerical byte selectors differ", row)
						}
					}
				}
			}
		}
	}
}

func TestX86CLMULNoMemoryOrUnknownResultPermission(t *testing.T) {
	for _, row := range []string{
		"PCLMULQDQ $0,(AX),X1", "PCLMULQDQ $0,·data(SB),X1",
		"VPCLMULQDQ $0,(AX),X1,X2", "VPCLMULQDQ $0,(AX),Y1,Y2", "VPCLMULQDQ $0,(AX),Z1,Z2",
	} {
		ins := x86ScalarLaneInstruction(t, row)
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z1": ^uint64(0)}}
		if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &state, nil) || len(ins.x86CallerMemory) != 0 {
			t.Fatal("shape or selected qword invented caller memory authority", row)
		}
		result := x86ResultState{pointerGP: [16]bool{true}}
		result.xmm[1] = 0xffff
		if x86ResultTransfer(ins, &result, nil, 0, "amd64") {
			t.Fatal("pointer identity or SB spelling invented readable bytes", row)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, missing := range []int{0, 1, 2, 3} {
			body := "MOVL $7,AX\n"
			for lane := 0; lane < 4; lane++ {
				if lane != missing {
					body += fmt.Sprintf("PINSRD $%d,AX,X%d\n", lane%2, lane/2)
				}
			}
			body += "PCLMULQDQ $0,X0,X1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("a partially missing selected qword acquired numerical result bytes", arch, missing, err)
			}
		}
	}
}

func TestX86CLMULScalarResultWholeSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, immediate := range []int{0, 1, 16, 17} {
			t.Run(fmt.Sprintf("%s/%d", arch, immediate), func(t *testing.T) {
				// Separate 32-bit insertions initialize only each selected qword;
				// the opposite halves deliberately retain unknown input bytes.
				body := "MOVL $7,AX\n"
				for operand, selector := range []int{immediate >> 4 & 1, immediate & 1} {
					for half := 0; half < 2; half++ {
						body += fmt.Sprintf("PINSRD $%d,AX,X%d\n", selector*2+half, operand)
					}
				}
				body += fmt.Sprintf("PCLMULQDQ $%d,X0,X1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+0(FP)\nRET", immediate)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value() uint32", body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); err != nil {
						t.Errorf("selected qword result failed: %v", err)
					}
				}
			})
		}
	}
}
