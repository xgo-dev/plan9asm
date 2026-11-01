package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86SegmentQueryCompleteInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for complete selector-query objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ := 8, "MOVQ", "uint64"
			if target.arch == "386" {
				word, move, typ = 4, "MOVL", "uint32"
			}
			var source, declarations strings.Builder
			functions, nativeReads := 0, 0
			for _, row := range x86SegmentQueryOracle {
				if target.arch == "386" && row.bytes == 8 {
					continue
				}
				for _, role := range []string{"register", "FP", "native"} {
					name := fmt.Sprintf("Query%s%s", row.op, role)
					parameter, selector := "uint16", "AX"
					prepare := "MOVW selector+0(FP),AX\n"
					if role == "FP" {
						selector, prepare = "selector+0(FP)", ""
					} else if role == "native" {
						parameter, selector = "*uint16", "(AX)"
						prepare = move + " selector+0(FP),AX\n"
						nativeReads++
					}
					query, result := row.op+" "+selector, "CX"
					if row.bytes != 0 {
						query += ",CX"
					} else {
						result = "DX"
					}
					body := prepare + move + " $0x13572468,CX\nSTC\n" + query + "\n"
					if row.bytes == 0 {
						body += "SETEQ DL\nMOVBLZX DL,DX\n"
					}
					body += fmt.Sprintf("%s %s,ret0+%d(FP)\nRET\n", move, result, word)
					declaration := fmt.Sprintf("func Value(selector %s) %s", parameter, typ)
					_, _, _, original := x86ResultInitializationFixture(t, target.arch, declaration, body)
					source.WriteString(strings.Replace(original, "Value(SB)", name+"(SB)", 1))
					declarations.WriteString(strings.Replace(declaration, "Value(", name+"(", 1) + "\n")
					functions++
				}
			}
			want := 24
			if target.arch == "386" {
				want = 18
			}
			if functions != want || functions > 64 {
				t.Fatal("complete bounded selector-query object inventory changed", functions, want)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized selector-query public objects rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "load volatile i16, ptr") != nativeReads {
							t.Fatal("native selectors lost their exact two-byte access", nativeReads)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86SegmentQueryNativeReaderSourceBoundaries(t *testing.T) {
	for _, row := range x86SegmentQueryOracle {
		for _, arch := range []string{"amd64", "386"} {
			if arch == "386" && row.bytes == 8 {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				text := row.op + " (BX)"
				if row.bytes != 0 {
					text += ",CX"
				}
				ins := x86ScalarLaneInstruction(t, text)
				initial := x86ResultState{flags: x86ByteFlagCF, direction: x86ResultDirectionBackward}
				initial.pointerGP[3] = true
				initial.gp[1] = 0xff
				state := initial.clone()
				if got, known := x86ResultSegmentQueryStep(ins, &state, nil, arch, false); !known || got || !reflect.DeepEqual(state, initial) {
					t.Fatal("standalone shape manufactured native selector bytes")
				}
				if got, known := x86ResultSegmentQueryStep(ins, &state, nil, arch, true); !known || !got ||
					state.flags != x86ByteFlagCF|x86ByteFlagZF || state.direction != initial.direction || !state.pointerGP[3] {
					t.Fatal("paired m16 continuation lost its precise FLAGS/address effects")
				}
				for _, mutation := range []string{"pointer", "old", "encoded", "raw", "segment", "address", "return"} {
					if mutation == "old" && row.bytes == 0 {
						continue
					}
					changed, state := ins, initial.clone()
					switch mutation {
					case "pointer":
						state.pointerGP[3] = false
					case "old":
						state.gp[1] = 0
					case "encoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "address":
						changed.x86AddressBits = 32
					case "return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					}
					before := state.clone()
					if got, _ := x86ResultSegmentQueryStep(changed, &state, nil, arch, true); got || !reflect.DeepEqual(state, before) {
						t.Fatal("native continuation supplied missing input or mutated a rejected state", mutation)
					}
				}
			})
		}
	}
}

func TestX86SegmentQueryVoidAndUnusedBoolRetainInputs(t *testing.T) {
	for _, row := range x86SegmentQueryOracle {
		for _, arch := range []string{"amd64", "386"} {
			if arch == "386" && row.bytes == 8 {
				continue
			}
			for _, signature := range []string{"func Value()", "func Value(unused bool)"} {
				t.Run(arch+"/"+row.op+"/"+signature, func(t *testing.T) {
					move := "MOVQ"
					triple := "x86_64-unknown-linux-gnu"
					if arch == "386" {
						move, triple = "MOVL", "i386-unknown-linux-gnu"
					}
					query := row.op + " AX"
					if row.bytes != 0 {
						query += ",CX"
					}
					args := 0
					if strings.Contains(signature, "unused bool") {
						args = 1
					}
					for _, inputs := range []string{"MOVW $0,AX\n" + move + " $7,CX\n", move + " $7,CX\n", "MOVB $0,AL\n" + move + " $7,CX\n"} {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n", args) + inputs + query + "\nRET\n"
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, signature, arch, triple, api)
							if strings.HasPrefix(inputs, "MOVW") {
								if err != nil || ir == "" {
									t.Fatal("complete Void query inputs rejected", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void or unused bool hid missing selector bytes", api, err)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86SegmentQueryRejectsBeforeDispatchMutation(t *testing.T) {
	for _, row := range x86SegmentQueryOracle {
		original := x86SegmentQueryOracleInstruction(t, row.op, row.bytes != 0)
		for _, mutation := range []string{"identity", "suffix", "source", "count", "index"} {
			ins := original
			ins.Args = append([]Operand(nil), original.Args...)
			op := ins.Op
			switch mutation {
			case "identity":
				ins.Op = "MOVL"
			case "suffix":
				op, ins.Op = Op(row.op+".Z"), Op(row.op+".Z")
			case "source":
				ins.Args[0] = Operand{Kind: OpImm, Imm: 0}
			case "count":
				ins.Args = append(ins.Args, Operand{Kind: OpReg, Reg: DX})
			case "index":
				ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: BX, Index: SP, Scale: 2}}
			}
			var output strings.Builder
			context := &amd64Ctx{goarch: "amd64", b: &output}
			if known, terminated, err := context.lowerSegmentQuery(op, ins); !known || terminated || err == nil || output.Len() != 0 {
				t.Fatal("invalid complete query shape emitted partial IR", row.op, mutation, err, output.String())
			}
		}
	}
}

func TestX86SegmentQueryConditionalDwordNeverInventsCanonicalHighBytes(t *testing.T) {
	for _, op := range []string{"LARL", "LSLL"} {
		ins := x86SegmentQueryOracleInstruction(t, op, true)
		for _, upper := range []uint8{0, 0x50, 0xf0} {
			before := [16]uint8{0xa5, upper | 0x0f, 0x5a}
			after := x86RegisterCanonicalBytesAfter(ins, before, "amd64")
			if after[0] != before[0] || after[1] != upper || after[2] != before[2] {
				t.Fatal("conditional dword write manufactured canonical upper bytes", op, before, after)
			}
		}
	}
}
