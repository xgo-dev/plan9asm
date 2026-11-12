package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86SelfCMPCompleteFlagsWithoutNumericalInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := "BWLQ"
		if arch == "386" {
			widths = "BWL"
		}
		for _, width := range widths {
			registers := []string{"AX", "CX", "DX", "BX", "SI", "DI"}
			if arch == "386" {
				registers = append(registers, "BP")
			} else {
				registers = append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
			}
			if width == 'B' {
				registers = []string{"AX", "CX", "DX", "BX", "AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"}
				if arch == "amd64" {
					registers = append(registers, "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
				}
			}
			for _, register := range registers {
				t.Run(fmt.Sprintf("%s/CMP%c/%s", arch, width, register), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("CMP%c %s,%s", width, register, register))
					state := x86ResultState{direction: x86ResultDirectionBackward}
					state.pointerGP[0], state.callerAddressGP[0], state.callerAddressOrigin[0] = true, true, 5
					expected := state.clone()
					expected.flags = x86ByteFlagsAll
					if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, expected) {
						t.Fatal("self comparison needs no source value and must define only the six status flags")
					}
				})
			}
		}
		for _, aliases := range [][2]string{{"AX", "AL"}, {"AL", "AX"}, {"CX", "CL"}, {"DX", "DL"}, {"BX", "BL"}} {
			t.Run(arch+"/same-low-byte/"+aliases[0]+"/"+aliases[1], func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "CMPB "+aliases[0]+","+aliases[1])
				state := x86ResultState{direction: x86ResultDirectionForward}
				expected := state.clone()
				expected.flags = x86ByteFlagsAll
				if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, expected) {
					t.Fatal("equal physical byte aliases were treated as different values")
				}
			})
		}
		for _, source := range []string{"CMPB AX,AH", "CMPB AH,AX", "TESTB AX,AX", "CMPL (AX),AX"} {
			t.Run(arch+"/distinct-read/"+source, func(t *testing.T) {
				state := x86ResultState{}
				if x86ResultTransfer(x86ScalarLaneInstruction(t, source), &state, nil, 0, arch) {
					t.Fatal("different byte, TEST or native memory borrowed self-CMP's value-independent role")
				}
			})
		}
	}
}

func TestX86SelfCMPThreeAPIsKeepNumericalAndPhysicalBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := "BWLQ"
		if target.arch == "386" {
			widths = "BWL"
		}
		for _, width := range widths {
			rows := []struct {
				name, body string
				accepted   bool
			}{
				{"flags-only", fmt.Sprintf("CMP%c AX,AX\nMOVL $0,BX\nSETEQ BL\nMOVL BX,ret+RESULT(FP)", width), true},
				{"not-NUM", fmt.Sprintf("CMP%c AX,AX\nMOVL AX,ret+RESULT(FP)", width), false},
				{"different-inputs", fmt.Sprintf("CMP%c AX,BX\nMOVL $7,ret+RESULT(FP)", width), false},
				// TEST always clears CF, but its ZF still depends on the input.
				{"TEST-independent-flags", fmt.Sprintf("TEST%c AX,AX\nMOVL $0,BX\nSETCS BL\nMOVL BX,ret+RESULT(FP)", width), true},
				{"TEST-reads-input", fmt.Sprintf("TEST%c AX,AX\nMOVL $0,BX\nSETEQ BL\nMOVL BX,ret+RESULT(FP)", width), false},
				{"SP-still-physical", fmt.Sprintf("CMP%c SP,SP\nMOVL $7,ret+RESULT(FP)", width), false},
			}
			if target.arch == "amd64" {
				rows = append(rows, struct {
					name, body string
					accepted   bool
				}{"BP-still-physical", fmt.Sprintf("CMP%c BP,BP\nMOVL $7,ret+RESULT(FP)", width), false})
			}
			for _, row := range rows {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/CMP%c/%s/%s", target.triple, width, row.name, api), func(t *testing.T) {
						source := x86ResultGPSIMDAdmissionSource(t, target.arch, "func view() uint32", row.body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api)
						if row.accepted {
							if err != nil || ir == "" {
								t.Fatal("self-CMP status was not available", err)
							}
						} else if err == nil || ir != "" {
							t.Fatal("self comparison granted an input value or a different operand role", err)
						}
					})
				}
			}
		}
	}
}
