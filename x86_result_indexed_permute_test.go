package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86IndexedPermuteResultNames = []string{
	"VPERMB", "VPERMW", "VPERMI2B", "VPERMI2W", "VPERMI2D", "VPERMI2Q", "VPERMI2PS", "VPERMI2PD",
	"VPERMT2B", "VPERMT2W", "VPERMT2D", "VPERMT2Q", "VPERMT2PS", "VPERMT2PD",
}

func TestX86IndexedPermuteResultRequiresCompleteTablesIndicesAndMerge(t *testing.T) {
	for _, op := range x86IndexedPermuteResultNames {
		for axis, bank := range []string{"X", "Y", "Z"} {
			width := 16 << axis
			for _, mode := range []string{"plain", "merge", "zero"} {
				t.Run(op+"/"+bank+"/"+mode, func(t *testing.T) {
					mask, suffix := "", ""
					if mode != "plain" {
						mask = "K1,"
					}
					if mode == "zero" {
						suffix = ".Z"
					}
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s%s %s0,%s1,%s%s2", op, suffix, bank, bank, mask, bank))
					inputs := 2
					if strings.HasPrefix(op, "VPERMI2") || strings.HasPrefix(op, "VPERMT2") || mode == "merge" {
						inputs = 3
					}
					for input := 0; input < inputs; input++ {
						for missing := -1; missing < width; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, masks: [8]bool{1: true}}
							for reg := 0; reg < 3; reg++ {
								bits := ^uint64(0)
								if reg == input && missing >= 0 {
									bits &^= uint64(1) << uint(missing)
								}
								state.writeVector(reg, 64, bits, false)
							}
							before := state.clone()
							accepted, known := x86ResultIndexedPermuteStep(ins, &state, nil, "amd64")
							if !known || accepted != (missing < 0) {
								t.Fatal("table/index/merge byte dependency lost", input, missing, accepted, known)
							}
							if missing >= 0 && !reflect.DeepEqual(state, before) {
								t.Fatal("failed dependency changed source facts")
							}
						}
					}
				})
			}
		}
	}
}

func x86IndexedPermuteResultFixture(op, bank, mode, source string) string {
	mask := ""
	if mode != "plain" {
		mask = "K1,"
	}
	if mode == "zero" {
		op += ".Z"
	}
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nKMOVD AX,K1\n"+
		"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nVPXORD Z3,Z3,Z3\n"+
		"%s %s,%s1,%s%s2\nVPCOMPRESSQ Z2,K1,Z3\nPEXTRD $0,X3,AX\nMOVL AX,ret+0(FP)\nRET\n",
		op, source, bank, mask, bank)
}

func TestX86IndexedPermuteInitializedResultWholeFamily(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			source.WriteString("GLOBL table<>(SB),8,$64\n")
			var names []string
			for _, op := range x86IndexedPermuteResultNames {
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if target.arch == "386" && mode != "plain" {
							continue // Four named operands exceed cmd/asm's 386 frontend.
						}
						inputs := []string{bank + "0", "table<>(SB)"}
						broadcast := !strings.HasSuffix(op, "B") && !strings.HasSuffix(op, "W")
						if broadcast {
							inputs = append(inputs, "broadcast")
						}
						for _, input := range inputs {
							member := op
							if input == "broadcast" {
								member, input = op+".BCST", "table<>(SB)"
							}
							body := x86IndexedPermuteResultFixture(member, bank, mode, input)
							name := fmt.Sprintf("Value%d", len(names))
							names = append(names, name)
							source.WriteString(strings.ReplaceAll(body, "Value", name))
							declarations.WriteString("func " + name + "() uint32\n")
						}
					}
				}
			}
			want := 324
			if target.arch == "386" {
				want = 108
			}
			if len(names) != want {
				t.Fatal("independent whole-family result inventory changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized indexed-permute family rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
				})
			}
		})
	}
}

func TestX86IndexedPermuteResultInputsStayIndependent(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, op := range x86IndexedPermuteResultNames {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, missing := range []string{"Z0", "Z1", "result"} {
					source := x86IndexedPermuteResultFixture(op, bank, "plain", bank+"0")
					if missing == "result" {
						source = strings.Replace(source, "MOVL AX,ret+0(FP)", "NOP", 1)
					} else {
						source = strings.Replace(source, fmt.Sprintf("VPXORD %s,%s,%s", missing, missing, missing), "NOP", 1)
					}
					t.Run(arch+"/"+op+"/"+bank+"/"+missing, func(t *testing.T) {
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							if _, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("indexed-permute acquired an unknown input/result", api, err)
							}
						}
					})
				}
			}
		}
	}
}
