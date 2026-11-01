package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestX86InLanePermuteOriginalConformanceThreeAPIObjects(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	const header = "TEXT ·inLaneFloatingPermuteSemantics(SB), NOSPLIT, $0-24\n"
	start := strings.Index(string(data), header)
	if start < 0 {
		t.Fatal("complete original in-lane permute function missing")
	}
	end := strings.Index(string(data[start:]), "\n\tRET\n")
	if end < 0 {
		t.Fatal("complete original in-lane permute return missing")
	}
	source := "#include \"textflag.h\"\n" + string(data[start:start+end+len("\n\tRET\n")])
	x86PackedFaultProgramObjects(t, source,
		"func inLaneFloatingPermuteSemantics(out *[144]byte, data *[32]byte, control *[32]byte)")
}

func x86InLanePermuteInitializedSource(arch string) (string, string, int) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	count := 0
	for _, op := range []string{"VPERMILPS", "VPERMILPD"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, immediate := range []bool{false, true} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if arch == "386" && mode != "plain" {
						continue // Real Go named four-operand rows are not mode32 inputs.
					}
					name := fmt.Sprintf("Permute%d", count)
					fmt.Fprintf(&declarations, "func %s(out *[66]byte, data *[64]byte, control *[64]byte)\n", name)
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s out+0(FP),DI\n%s data+%d(FP),BX\n%s control+%d(FP),CX\n",
						name, 3*word, move, move, word, move, 2*word)
					zero := "VPXOR"
					if bank == "Z" {
						zero = "VPXORD"
					}
					for register := 0; register < 3; register++ {
						fmt.Fprintf(&source, "%s %s%d,%s%d,%s%d\n", zero, bank, register, bank, register, bank, register)
					}
					mask, suffix, memory := "", "", "(CX)"
					if immediate {
						memory = "(BX)"
					}
					if mode != "plain" {
						mask = ",K1"
						value := -1
						if mode == "zero" {
							value, suffix = 0, ".BCST.Z"
						} else {
							memory = bank + "0"
						}
						fmt.Fprintf(&source, "MOVL $%d,AX\nKMOVD AX,K1\n", value)
					}
					source.WriteString("MOVL $5,DX\nCMPL DX,$3\nSTD\n")
					operands := memory + "," + bank + "1"
					if immediate {
						operands = "$0x1b," + memory
					}
					fmt.Fprintf(&source, "%s%s %s%s,%s2\nVMOVUPS %s2,(DI)\nSETCS 64(DI)\nSETOS 65(DI)\nCLD\nRET\n",
						op, suffix, operands, mask, bank, bank)
					count++
				}
			}
		}
	}
	return source.String(), declarations.String(), count
}

func TestX86InLanePermuteInitializedCompleteFamilyNativeReads(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, count := x86InLanePermuteInitializedSource(target.arch)
			want := 36
			if target.arch == "386" {
				want = 12
			}
			if count != want {
				t.Fatal("orthogonal initialized family directory changed", count, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized in-lane permute family rejected", err)
					}
					for index := 0; index < count; index++ {
						body := x86StringMemoryFunction(t, ir, fmt.Sprintf("Permute%d", index))
						// Plain and zero/BCST functions have only the permute's
						// input read; preceding vector producers are register XORs.
						memory := target.arch == "386" || index%3 != 1
						if memory && !strings.Contains(body, "load volatile ") {
							t.Fatal("native E4NF tuple/broadcast read can disappear for dead or zero-mask results", index)
						}
					}
					for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86PackedStringCompileObject(t, llc, target.triple, input, "-O0")
					}
				})
			}
		})
	}
}

func TestX86InLanePermuteRegisterEffectsPreserveIndependentState(t *testing.T) {
	var directory strings.Builder
	directory.WriteString("TEXT effectrows(SB),4,$0-0\n")
	var rows []string
	for _, op := range []string{"VPERMILPS", "VPERMILPD"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, first := range []string{"$0x1b", bank + "0"} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					mask, suffix := "", ""
					if mode != "plain" {
						mask = ",K1"
					}
					if mode == "zero" {
						suffix = ".Z"
					}
					row := fmt.Sprintf("%s%s %s,%s1%s,%s2", op, suffix, first, bank, mask, bank)
					rows = append(rows, row)
					fmt.Fprintln(&directory, row)
				}
			}
		}
	}
	directory.WriteString("RET\n")
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", directory.String())
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil || len(effect.operands) == 0 || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
				t.Fatal("complete family lacks a typed input/output effect preserving FLAGS", err)
			}
			state := x86FloatingHelperInitializedState()
			before := state.clone()
			if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
				t.Fatal("initialized register permute lost numerical bytes or changed independent state")
			}
			if len(ins.Args) == 4 {
				state = before.clone()
				state.masks[1] = false
				initial := state.clone()
				if x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, initial) {
					t.Fatal("unknown mask acquired a result or partly changed state")
				}
			}
			for source := 0; source < 2; source++ {
				if ins.Args[0].Kind == OpImm && source == 0 {
					continue
				}
				hole := 0
				if ins.Args[0].Kind == OpImm && strings.HasPrefix(row, "VPERMILPD") {
					// Independent SDM selector: imm8=0x1b has low bits 11,
					// so both outputs in the first pair read qword one.
					hole = 8
				}
				state = before.clone()
				state.writeVector(source, 64, state.vectorBytes(source)&^(uint64(1)<<uint(hole)), false)
				initial := state.clone()
				accepted := x86ResultTransfer(ins, &state, nil, 0, "amd64")
				width := amd64VectorByteWidth(ins.Args[len(ins.Args)-1].Reg)
				known := x86CallerVectorByteMask(int64(width))
				if accepted && state.vectorBytes(2)&known == known || !accepted && !reflect.DeepEqual(state, initial) {
					t.Fatal("missing selected data/control byte became NUM or failed transfer partly mutated state", source, hole)
				}
			}
		})
	}
}

func TestX86InLanePermuteVoidReadsNeedActualInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		for _, op := range []string{"VPERMILPS", "VPERMILPD"} {
			for _, variable := range []bool{false, true} {
				for _, missing := range []string{"none", "pointer", "index", "data"} {
					if !variable && missing == "data" {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/variable=%t/%s", target.triple, op, variable, missing), func(t *testing.T) {
						prefix := move + " p+0(FP),BX\n"
						if missing == "pointer" {
							prefix = ""
						}
						address := "(BX)"
						if missing == "index" {
							address = "(BX)(DX*2)"
						}
						operands := "$0x1b," + address
						if variable {
							operands = address + ",X1"
							if missing != "data" {
								prefix += "VPXOR X1,X1,X1\n"
							}
						}
						source := fmt.Sprintf("TEXT Value(SB),4,$0-%d\n%s%s %s,X2\nRET\n", word, prefix, op, operands)
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte)", target.arch, target.triple, api)
								if missing == "none" {
									if err != nil || !strings.Contains(ir, "load volatile ") {
										t.Fatal("dead native permute lost its exact observable input read", err)
									}
								} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("Void invented a missing pointer/index/numerical input", err)
								}
							})
						}
					})
				}
			}
		}
	}
}
