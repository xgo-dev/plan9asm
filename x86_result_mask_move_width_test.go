package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent data widths: a K-to-GP transfer also defines the architectural
// zero remainder, unlike a partial ordinary MOVB/MOVW register write.
var x86ResultMaskMoveWidthOracle = []struct {
	op   string
	bits int
}{
	{"KMOVB", 8}, {"KMOVW", 16}, {"KMOVD", 32}, {"KMOVQ", 64},
}

func TestX86MaskMoveGPResultFullWordDefinedness(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ResultMaskMoveWidthOracle {
			for mask := 0; mask < 8; mask++ {
				t.Run(fmt.Sprintf("%s/%s/K%d", arch, row.op, mask), func(t *testing.T) {
					instruction := x86ScalarLaneInstruction(t, fmt.Sprintf("%s K%d,BX", row.op, mask))
					for seed := 0; seed < 256; seed++ {
						for _, initialized := range []bool{false, true} {
							state := x86ResultState{flags: x86ByteFlagsAll}
							state.masks[mask] = initialized
							state.gp[3], state.pointerGP[3] = uint8(seed), true
							before := state.clone()
							accepted := x86ScalarFPResultTransfer(instruction, &state, nil, 0, arch)
							want := initialized
							if accepted != want {
								t.Fatal("mask move acquired a missing input or physical width", seed, initialized, accepted, want)
							}
							if !want {
								if !reflect.DeepEqual(state, before) {
									t.Fatal("rejected mask transfer changed numerical state")
								}
								continue
							}
							before.gp[3], before.pointerGP[3] = 0xff, false
							if !reflect.DeepEqual(state, before) {
								t.Fatal("GP zero extension lost complete numerical bytes or changed unrelated state", seed, state.gp[3])
							}
						}
					}
				})
			}
		}
	}
}

func x86ResultMaskMoveWidthFixture(arch string) (string, string, []string) {
	word, move, count := 8, "MOVQ", "POPCNTQ"
	registers := []string{"AX", "BX", "CX", "DX", "SI", "DI", "R8", "R15"}
	if arch == "386" {
		word, move, count = 4, "MOVL", "POPCNTL"
		registers = registers[:6]
	}
	var source, declarations strings.Builder
	var names []string
	for _, row := range x86ResultMaskMoveWidthOracle {
		for _, destination := range registers {
			for _, mask := range []string{"K0", "K7"} {
				input := "DX"
				if destination == input {
					input = "AX"
				}
				name := fmt.Sprintf("Mask%d", len(names))
				names = append(names, name)
				fmt.Fprintf(&declarations, "func %s(x uintptr) uintptr\n", name)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),%s\n"+
					"KMOVD %s,K1\nVPXORD Z0,Z0,Z0\nVPXORD Z7,Z7,Z7\nVPCOMPRESSQ Z0,K1,Z7\n"+
					"%s %s,%s\n%s %s,%s\n%s %s,%s\n%s %s,ret+%d(FP)\nRET\n",
					name, 2*word, move, input, input, row.op, input, mask, row.op, mask, destination,
					count, destination, destination, move, destination, word)
			}
		}
	}
	return source.String(), declarations.String(), names
}

func TestX86MaskMoveGPResultFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86ResultMaskMoveWidthFixture(target.arch)
			want := 64
			if target.arch == "386" {
				want = 48
			}
			if len(names) != want {
				t.Fatal("complete mask/width/register denominator changed", len(names), want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete mask-to-GP count sequence rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86MaskMoveGPResultCannotInventInputOrBoolCanonicality(t *testing.T) {
	for _, row := range x86ResultMaskMoveWidthOracle {
		for name, body := range map[string]string{
			"unknown-mask": row.op + " K1,BX\nMOVB BX,ret+8(FP)\nRET\n",
			"not-bool": "MOVQ x+0(FP),AX\nKMOVQ AX,K1\nMOVL $1,BX\n" +
				row.op + " K1,BX\nMOVB BX,ret+8(FP)\nRET\n",
		} {
			t.Run(row.op+"/"+name, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-9\n" + body
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(x uint64) bool", "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("mask transfer invented numerical input or a canonical bool", api, err)
					}
				}
			})
		}
	}
}
