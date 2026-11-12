package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestX86LegacyPackedRegisterMoveSparseBytesAndPreservedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86LegacyMoveNativeOracle {
			for _, operands := range []string{"X0,X1", "X1,X1", "X7,X0"} {
				t.Run(arch+"/"+row.name+"/"+operands, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.name+" "+operands)
					source, _ := amd64ParseXReg(ins.Args[0].Reg)
					destination, _ := amd64ParseXReg(ins.Args[1].Reg)
					masks := []uint16{0, 1, 0x8000, 0xa55a, 0xffff}
					for missing := 0; missing < 16; missing++ {
						masks = append(masks, 0xffff&^(uint16(1)<<uint(missing)))
					}
					for _, mask := range masks {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.xmm[source] = mask
						state.vectorUpper[source] = 0x56789abcdef00000
						state.vectorUpper[destination] = 0xaabcde0123450000
						state.gp[0], state.canonicalGP[0], state.pointerGP[0] = 0xff, 1, true
						state.masks[1] = true
						before, expected := state.clone(), state.clone()
						expected.xmm[destination] = mask
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, expected) {
							t.Fatalf("source byte mask %04x was widened or lost, or unrelated state changed", mask)
						}
						strict := before.clone()
						if accepted := x86ResultTransfer(ins, &strict, nil, 0, arch); accepted != (mask == 0xffff) {
							t.Fatal("private partial-copy effect changed the independent complete-input query", mask, accepted)
						}
						if mask != 0xffff {
							physical := ins
							physical.x86Encoded = true
							strict = before.clone()
							if x86ScalarFPResultTransfer(physical, &strict, nil, 0, arch) || !reflect.DeepEqual(strict, before) {
								t.Fatal("physical/raw source borrowed the named sparse-copy continuation")
							}
						}
					}
				})
			}
		}
	}
}

func TestX86LegacyPackedRegisterMoveSelectedByteThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		result, extent, triple := 8, 12, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			result, extent, triple = 4, 8, "i386-unknown-linux-gnu"
		}
		for _, row := range x86LegacyMoveNativeOracle {
			for _, selected := range []int{7, 8} {
				t.Run(fmt.Sprintf("%s/%s/byte%d", arch, row.name, selected), func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\nMOVB c+0(FP),AX\nPINSRB $7,AX,X0\n%s X0,X1\nPEXTRB $%d,X1,AX\nMOVL AX,ret+%d(FP)\nRET\n", extent, row.name, selected, result)
					goAssemblerOracleOutput(t, arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func view(c byte) uint32\n", arch, triple, api)
							if selected == 7 {
								if err != nil || ir == "" {
									t.Fatal("selected byte lost after a legacy register copy", err)
								}
							} else if arch == "amd64" {
								x86VectorScratchCodegenControl(t, source, "func view(c byte) uint32\n", arch, triple, ir, err)
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unknown adjacent source byte became observable", err)
							}
						})
					}
				})
			}
		}
	}
}
