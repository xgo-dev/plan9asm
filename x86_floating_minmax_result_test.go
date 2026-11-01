package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86FloatingMinMaxCase struct {
	op             string
	bits           int
	legacy, scalar bool
}

// Independent list of the eight yxm opcodes and eight AVX _yvaddpd/_yvaddsd
// members. MIN/MAX optab attributes enable SAE, not ADD/MUL's ER controls.
var x86FloatingMinMaxCases = []x86FloatingMinMaxCase{
	{"MINPS", 32, true, false}, {"MINPD", 64, true, false},
	{"MINSS", 32, true, true}, {"MINSD", 64, true, true},
	{"MAXPS", 32, true, false}, {"MAXPD", 64, true, false},
	{"MAXSS", 32, true, true}, {"MAXSD", 64, true, true},
	{"VMINPS", 32, false, false}, {"VMINPD", 64, false, false},
	{"VMINSS", 32, false, true}, {"VMINSD", 64, false, true},
	{"VMAXPS", 32, false, false}, {"VMAXPD", 64, false, false},
	{"VMAXSS", 32, false, true}, {"VMAXSD", 64, false, true},
}

func TestX86FloatingMinMaxIndependentNativeISAProfiles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FloatingMinMaxCases {
			for _, width := range []int{16, 32, 64} {
				if (row.legacy || row.scalar) && width != 16 {
					continue
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				instruction := row.op + " " + bank + "0," + bank + "1," + bank + "2"
				want := "+avx"
				if width == 64 {
					want = "+avx512f"
				}
				if row.legacy {
					instruction = row.op + " X0,X1"
					want = "+sse"
					if row.bits == 64 {
						want = "+sse2"
					}
				}
				t.Run(fmt.Sprintf("%s/%s/%d", arch, row.op, width), func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0])
					if !strings.Contains(features, want) {
						t.Fatalf("MIN/MAX borrowed a sibling ISA: want %s in %q", want, features)
					}
				})
			}
		}
	}
}

func TestX86FloatingMinMaxCompleteNumericalTransfers(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FloatingMinMaxCases {
			for _, width := range []int{16, 32, 64} {
				if (row.legacy || row.scalar) && width != 16 {
					continue
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				instruction := row.op + " " + bank + "0," + bank + "1," + bank + "2"
				if row.legacy {
					instruction = row.op + " X0,X1"
				}
				t.Run(fmt.Sprintf("%s/%s/%d", arch, row.op, width), func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					// Parse retains original TEXT metadata; transfer exactly the
					// independently specified arithmetic instruction, not TEXT.
					ins := file.Funcs[0].Instrs[1]
					if ins.Op != Op(row.op) {
						t.Fatal("independent MIN/MAX fixture instruction changed", ins.Op)
					}
					active := width
					if row.scalar {
						active = row.bits / 8
					}
					mask := x86CallerVectorByteMask(int64(active))
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.writeVector(0, width, mask, true)
					state.writeVector(1, width, mask, true)
					if row.scalar {
						state.xmm[1] |= 0xa500 // Partly known passthrough, not invented zeros.
					}
					want := state
					destination := 2
					known := mask
					if row.scalar {
						known |= uint64(state.xmm[1]) &^ mask
					}
					if row.legacy {
						destination = 1
						known |= state.vectorBytes(1)
					}
					want.writeVector(destination, width, known, row.legacy)
					accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
					if !accepted || !reflect.DeepEqual(state, want) {
						t.Fatalf("MIN/MAX effects: accepted=%t xmm=%v want=%v upper=%v want=%v",
							accepted, state.xmm, want.xmm, state.vectorUpper, want.vectorUpper)
					}
				})
			}
		}
	}
}

func TestX86FloatingMinMaxVoidCannotBorrowImplementationInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86FloatingMinMaxCases {
			instruction := row.op + " X0,X1,X2"
			if row.legacy {
				instruction = row.op + " X0,X1"
			}
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				t.Run(target.triple+"/"+row.op+"/"+api, func(t *testing.T) {
					options := Options{Goarch: target.arch, TargetTriple: target.triple,
						Sigs:       map[string]FuncSig{"Value": {Name: "Value", Ret: Void}},
						ResolveSym: func(name string) string { return strings.TrimPrefix(name, "·") }}
					ir, err := x86PackedFloatStorageAPI(api, file, options)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("dead MIN/MAX borrowed implementation vector inputs", err)
					}
				})
			}
		}
	}
}

func TestX86FloatingMinMaxCompleteNativeObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("native MIN/MAX objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		counts := make(map[string]int)
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		index := 0
		for _, row := range x86FloatingMinMaxCases {
			for _, width := range []int{16, 32, 64} {
				if (row.legacy || row.scalar) && width != 16 {
					continue
				}
				name := fmt.Sprintf("minmax%d", index)
				index++
				counts[row.op]++
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				load := "VMOVUPS"
				if width == 16 {
					load = "MOVUPS"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s a+0(FP),AX\n%s b+%d(FP),BX\n%s out+%d(FP),CX\n",
					name, 3*word, move, move, word, move, 2*word)
				fmt.Fprintf(&source, "%s (AX),%s0\n%s (BX),%s1\n", load, bank, load, bank)
				if row.legacy {
					fmt.Fprintf(&source, "%s X0,X1\nMOVUPS X1,(CX)\nRET\n", row.op)
				} else {
					fmt.Fprintf(&source, "%s %s0,%s1,%s2\n%s %s2,(CX)\nRET\n", row.op, bank, bank, bank, load, bank)
				}
				fmt.Fprintf(&declarations, "func %s(a,b,out *byte)\n", name)
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete independent MIN/MAX source", err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for op, count := range counts {
						if strings.Count(text, "asm sideeffect \""+strings.ToLower(op)+" ") != count {
							t.Fatal("original MIN/MAX opcode or floating side effects disappeared", op)
						}
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			})
		}
	}
}
