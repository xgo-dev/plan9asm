package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Independent inventory from Go's complete AVPADD/AVPSUB encoder rows.
// Do not derive the expected family or byte dependencies from production specs.
var x86ResultVectorArithmeticNames = []struct {
	name string
	bits int
}{
	{"VPADDB", 8}, {"VPADDW", 16}, {"VPADDD", 32}, {"VPADDQ", 64},
	{"VPADDSB", 8}, {"VPADDSW", 16}, {"VPADDUSB", 8}, {"VPADDUSW", 16},
	{"VPSUBB", 8}, {"VPSUBW", 16}, {"VPSUBD", 32}, {"VPSUBQ", 64},
	{"VPSUBSB", 8}, {"VPSUBSW", 16}, {"VPSUBUSB", 8}, {"VPSUBUSW", 16},
}

func TestX86VectorArithmeticIndependentResultConsumers(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, op := range x86ResultVectorArithmeticNames {
				for _, bank := range []string{"X", "Y", "Z"} {
					name := fmt.Sprintf("Arithmetic%d%s", index, bank)
					fmt.Fprintf(&declarations, "func %s(a,b uint64) uint32\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-20\nVZEROALL\nMOVQ a+0(FP),X0\nMOVQ b+8(FP),X1\n", name)
					fmt.Fprintf(&source, "%s %s0,%s1,%s1\nPEXTRD $0,X1,AX\nMOVL AX,ret+16(FP)\nRET\n", op.name, bank, bank, bank)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatalf("%s complete vector arithmetic lacks result effects: %v", api, err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, "vector-arithmetic-"+api)
				x86ResultInitializationObject(t, llc, target.triple, x86MulDivRoundOptimize(t, ir), "vector-arithmetic-"+api+"-O2")
			}
		})
	}
}

func TestX86VectorArithmeticSparseResultBytes(t *testing.T) {
	for _, op := range x86ResultVectorArithmeticNames {
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for masking := 0; masking < 3; masking++ {
				row := op.name
				if masking == 2 {
					row += ".Z"
				}
				row += " " + bank + "0," + bank + "1"
				if masking != 0 {
					row += ",K1"
				}
				row += "," + bank + "2"
				ins := x86ScalarLaneInstruction(t, row)
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						initial := [3]uint64{^uint64(0), ^uint64(0), ^uint64(0)}
						if missing >= 0 {
							initial[input] &^= uint64(1) << uint(missing)
						}
						state := x86ResultState{flags: x86ByteFlagsAll}
						for index, value := range initial {
							state.writeVector(index, 64, value, false)
						}
						state.masks[1] = true
						if !x86ResultTransfer(ins, &state, nil, 0, "amd64") {
							t.Fatal("missing numerical byte consumer", row)
						}
						var want uint64
						for output := 0; output < 64; output++ {
							known := true
							if output < width {
								start := output / (op.bits / 8) * (op.bits / 8)
								for source := start; source < start+op.bits/8; source++ {
									known = known && initial[0]>>uint(source)&1 != 0 && initial[1]>>uint(source)&1 != 0
								}
								if masking == 1 {
									known = known && initial[2]>>uint(output)&1 != 0
								}
							}
							if known {
								want |= uint64(1) << uint(output)
							}
						}
						if state.vectorBytes(2) != want || state.flags != x86ByteFlagsAll ||
							state.vectorBytes(0) != initial[0] || state.vectorBytes(1) != initial[1] {
							t.Fatalf("%s input=%d missing=%d: got=%x want=%x", row, input, missing, state.vectorBytes(2), want)
						}
					}
				}
			}
		}
	}
}

func TestX86VectorArithmeticResultMemoryAndMaskBoundaries(t *testing.T) {
	for _, op := range x86ResultVectorArithmeticNames {
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, broadcast := range []bool{false, true} {
				if broadcast && op.bits < 32 {
					continue
				}
				row, bytes := op.name, width
				if broadcast {
					row, bytes = row+".BCST", op.bits/8
				}
				row += ".Z value+0(FP)," + bank + "1,K1," + bank + "2"
				ins := x86ScalarLaneInstruction(t, row)
				for missing := -1; missing < 64; missing++ {
					for _, maskKnown := range []bool{false, true} {
						state := x86ResultState{fp: make([]bool, 64)}
						owned := make([]bool, 64)
						for i := range owned {
							owned[i], state.fp[i] = true, i != missing
						}
						state.writeVector(1, 64, ^uint64(0), false)
						state.masks[1] = maskKnown
						accepted := x86ResultTransfer(ins, &state, owned, 64, "amd64")
						want := maskKnown && (missing < 0 || missing >= bytes)
						if accepted != want || accepted && state.vectorBytes(2) != ^uint64(0) || len(ins.x86CallerMemory) != 0 {
							t.Fatal("mask/tuple invented bytes or caller permission", row, missing, maskKnown, accepted)
						}
					}
				}
			}
		}
		for _, source := range []string{"(AX)", "·unknown(SB)", "value-1(FP)"} {
			ins := x86ScalarLaneInstruction(t, op.name+" "+source+",X1,X2")
			state := x86ResultState{}
			state.xmm[1], state.pointerGP[0] = 0xffff, true
			if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
				t.Fatal("unproved memory acquired numerical authority", op.name, source)
			}
		}
	}
}

func TestX86VectorArithmeticSaturatingAddNativeReadEffects(t *testing.T) {
	for _, op := range []string{"VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			row := op + ".Z (DX)," + bank + "0,K1," + bank + "1"
			source := "TEXT ·view(SB),4,$0-16\nMOVQ p+0(FP),DX\nMOVQ mask+8(FP),AX\nKMOVQ AX,K1\nVZEROALL\n" + row + "\nRET\n"
			t.Run(row, func(t *testing.T) {
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *[64]byte, mask uint64)\n", "amd64", "x86_64-unknown-linux-gnu", "Go")
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if !strings.Contains(text, "load volatile") || !strings.Contains(text, "br i1") {
						t.Fatal("dead masked arithmetic lost conditional native reads")
					}
				}
			})
		}
	}
}

func TestX86VectorArithmeticSaturatingAddCompleteForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW"} {
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				var source, declarations strings.Builder
				count := 0
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, input := range []string{bank + "0", "value+0(FP)", "(AX)", "8(AX)(CX*2)", "·data(SB)"} {
						for masking := 0; masking < 3; masking++ {
							if target.arch == "386" && masking != 0 {
								continue
							}
							row := op
							if masking == 2 {
								row += ".Z"
							}
							row += " " + input + "," + bank + "1"
							if masking != 0 {
								row += ",K7"
							}
							row += "," + bank + "2"
							fmt.Fprintf(&declarations, "func Saturating%d(value [64]byte)\n", count)
							fmt.Fprintf(&source, "TEXT ·Saturating%d(SB),4,$0-64\n%s\nRET\n", count, row)
							count++
						}
					}
				}
				if count > 64 || target.arch == "amd64" && count != 45 || target.arch == "386" && count != 15 {
					t.Fatal("incomplete or oversized form batch", count)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				file := mustParseX86RawReturn(t, source.String())
				pkg := mustGoPackage(t, "arithmeticformats", "package arithmeticformats\n"+declarations.String())
				resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
				signatures, err := goSigsForAsmFile(pkg, file, resolve, target.arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				// Every original form and Go object remains. These unbound
				// functions lack vectors, masks and native addresses; syntax
				// objects cannot grant their missing public ABI0 inputs.
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), pkg, target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unbound saturating format invented source inputs", api, err)
					}
				}
				ir := x86ScalarFormatObjectUnit(t, file, signatures, target.arch, target.triple, 0)
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			})
		}
	}
}
