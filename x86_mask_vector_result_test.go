package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent lane dependencies: VPMOV*2M reads each lane's sign byte, not
// unrelated bytes. The production form is used only by the consumer under test.
func x86MaskVectorSignBytes(row string, width int) uint64 {
	lane := map[string]int{"B": 1, "W": 2, "D": 4, "Q": 8}[strings.TrimSuffix(strings.TrimPrefix(strings.Fields(row)[0], "VPMOV"), "2M")]
	if lane == 0 {
		panic("sign-byte oracle requires a vector-to-mask row")
	}
	var required uint64
	for offset := lane - 1; offset < width; offset += lane {
		required |= uint64(1) << uint(offset)
	}
	return required
}

func TestX86MaskVectorMissingSignBytesAndSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86OfficialMaskVectorRows(t) {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row)
				toVector := strings.HasPrefix(row, "VPMOVM2")
				width := 16
				if strings.Contains(row, "Y1") {
					width = 32
				} else if strings.Contains(row, "Z1") {
					width = 64
				}
				for missing := 0; missing < 64; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.masks[2] = true
					state.writeVector(1, 64, ^(uint64(1) << uint(missing)), false)
					want := state.clone()
					required := toVector
					if !toVector {
						required = x86MaskVectorSignBytes(row, width)&(uint64(1)<<uint(missing)) != 0
						if !required {
							want.masks[1] = true
						}
					}
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) == required || !reflect.DeepEqual(state, want) {
						t.Fatal("missing sign/mask input escaped or irrelevant byte became a dependency", missing)
					}
				}
				for _, raw := range []bool{false, true} {
					state := x86ResultState{}
					state.masks[1] = true
					state.writeVector(1, 64, ^uint64(0), false)
					before := state.clone()
					changed := ins
					if raw {
						changed.x86Encoded = true
					} else {
						changed.Op += ".Z"
					}
					if x86ScalarFPResultTransfer(changed, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
						t.Fatal("unbound physical source or reserved suffix borrowed a named numerical effect")
					}
				}
			})
		}
	}
}

func TestX86MaskVectorCompleteNumericalInputsAndUnaffectedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86OfficialMaskVectorRows(t) {
			for _, mask := range []string{"K0", "K7"} {
				t.Run(arch+"/"+strings.ReplaceAll(row, "K1", mask), func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, strings.ReplaceAll(row, "K1", mask))
					vector, width := 1, 16
					if strings.Contains(row, "Y1") {
						width = 32
					} else if strings.Contains(row, "Z1") {
						width = 64
					}
					maskIndex := 0
					if mask == "K7" {
						maskIndex = 7
					}
					toVector := strings.HasPrefix(row, "VPMOVM2")
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.gp[3], state.canonicalGP[3], state.pointerGP[3] = 0xa5, 0x11, true
					state.masks[2] = true
					state.writeVector(3, 64, 0x76543210fedcba98, false)
					known := uint64(0x13579bdf02468ace) &^ x86CallerVectorByteMask(int64(width))
					if toVector {
						state.masks[maskIndex] = true
					} else {
						known |= x86MaskVectorSignBytes(row, width)
					}
					state.writeVector(vector, 64, known, false)
					want := state.clone()
					if toVector {
						want.writeVector(vector, width, x86CallerVectorByteMask(int64(width)), false)
					} else {
						want.masks[maskIndex] = true
					}
					if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
						t.Fatal("complete mask/vector data effect is missing, over-reads lanes or changes unrelated state")
					}
				})
			}
		}
	}
}

func TestX86MaskVectorInitializedResultsThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, row := range x86OfficialMaskVectorRows(t) {
				for _, mask := range []string{"K0", "K7"} {
					name := fmt.Sprintf("MaskData%d", count)
					count++
					fmt.Fprintf(&declarations, "func %s(x uint64) uint64\n", name)
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\n", name)
					if strings.HasPrefix(row, "VPMOVM2") {
						fmt.Fprintf(&source, "KMOVQ x+0(FP),%s\n%s\nPEXTRD $0,X1,ret+8(FP)\nPEXTRD $1,X1,ret+12(FP)\n", mask, strings.ReplaceAll(row, "K1", mask))
					} else {
						fmt.Fprintf(&source, "VPXORD Z1,Z1,Z1\n%s\nKMOVQ %s,ret+8(FP)\n", strings.ReplaceAll(row, "K1", mask), mask)
					}
					source.WriteString("RET\n")
				}
			}
			if count != 48 {
				t.Fatal("incomplete independent Go-row/K0-K7 program union", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Error("initialized mask/vector programs lost their numerical effects", api, err)
					continue
				}
				if strings.Count(ir, "define i64 @") != count {
					t.Fatal("translation omitted an original mask/vector function", api)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86MaskVectorVoidInputsCannotBorrowImplementationZeros(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86OfficialMaskVectorRows(t) {
			if !strings.Contains(row, "X1") {
				continue // The independent unit/object axes already retain every X/Y/Z row.
			}
			for _, unusedBool := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/bool-%t", target.triple, row, unusedBool), func(t *testing.T) {
					declaration, extent := "func Value()", 0
					if unusedBool {
						declaration, extent = "func Value(flag bool)", 1
					}
					source := fmt.Sprintf("TEXT Value(SB),4,$0-%d\n%s\nRET\n", extent, strings.ReplaceAll(row, "K1", "K0"))
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("missing source mask/vector data became initialized private zeros", api, err)
						}
					}
				})
			}
		}
	}
}
