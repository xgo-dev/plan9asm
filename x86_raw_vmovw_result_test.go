package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Intel AVX512-FP16 section 5.61: both W values, two directions and
// register/m16 forms. GP destinations zero-extend; X writes clear wider aliases.
// https://cdrdv2-public.intel.com/678970/intel-avx512-fp16.pdf
func x86RawVMOVWResultFixture(name, arch string, load, wide, memory bool) (string, string) {
	move, word, result := "MOVQ", 8, 16
	if arch == "386" {
		move, word, result = "MOVL", 4, 8
	}
	general := 1 // CX is numerical, not the incoming pointer in AX.
	if memory {
		general = 0
	}
	source := fmt.Sprintf("TEXT %s(SB),4,$0-%d\n"+
		"%s p+0(FP),AX\nMOVL value+%d(FP),CX\nMOVL CX,X1\n",
		name, result+4, move, word)
	source += x86RawDisplacementDirectives(rawVMOVW(load, wide, 1, general, memory))
	if load || memory {
		source += "MOVL X1,BX\n"
	} else {
		source += "MOVL CX,BX\n"
	}
	source += fmt.Sprintf("MOVL BX,ret+%d(FP)\nRET\n", result)
	return source, fmt.Sprintf("func %s(p *byte,value uint32) uint32\n", name)
}

func TestX86RawVMOVWExactOriginAndNumericalState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, load := range []bool{false, true} {
			for _, memory := range []bool{false, true} {
				for _, wide := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/load=%t/memory=%t/wide=%t", arch, load, memory, wide), func(t *testing.T) {
						general := 1
						if memory {
							general = 0
						}
						file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+
							x86RawDisplacementDirectives(rawVMOVW(load, wide, 1, general, memory))+"RET\n")
						file, err := normalizeX86RawFile(file, arch)
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.pointerGP[0], state.gp[1], state.gp[2] = true, 3, 0x55
						state.writeVector(1, 64, 0xabcdef0123450003, false)
						before := state.clone()
						accepted, known := x86LoweredRawVMOVWResultStep(ins, &state, nil, 0, arch)
						want := before.clone()
						if load {
							want.writeVector(1, 64, ^uint64(0), false)
						} else if !memory {
							want.gp[1] = 0xff
						}
						if !accepted || !known || !reflect.DeepEqual(state, want) {
							t.Fatal("VMOVW lost low two bytes, upper zeroing or unrelated state")
						}
						if !load || !memory {
							for missing := uint(0); missing < 2; missing++ {
								partial := before.clone()
								if !load {
									partial.writeVector(1, 64, partial.vectorBytes(1)&^(1<<missing), false)
								} else {
									partial.gp[1] &^= 1 << missing
								}
								original := partial.clone()
								accepted, known := x86LoweredRawVMOVWResultStep(ins, &partial, nil, 0, arch)
								if accepted || !known || !reflect.DeepEqual(partial, original) {
									t.Fatal("VMOVW invented a missing low byte", missing)
								}
							}
						}
						for _, mutation := range []string{"encoding", "origin", "opcode", "operand", "address", "segment", "return", "literal"} {
							changed, rejected := ins, before.clone()
							switch mutation {
							case "encoding":
								changed.x86Encoded = false
							case "origin":
								changed.x86SourceRaw = nil
							case "opcode":
								changed.x86SourceRaw = &x86SourceRawInstruction{op: "VMOVD", args: ins.Args}
							case "operand":
								changed.Args = append([]Operand(nil), ins.Args...)
								changed.Args[0] = Operand{Kind: OpReg, Reg: "X2"}
							case "address":
								changed.x86AddressBits = 32
							case "segment":
								changed.x86SegmentPrefix = 0x64
							case "return":
								changed.x86RawNearReturn = new(x86RawNearReturnForm)
							case "literal":
								changed.x86RIPLiteral = true
							}
							accepted, known := x86LoweredRawVMOVWResultStep(changed, &rejected, nil, 0, arch)
							if accepted || !known || !reflect.DeepEqual(rejected, before) {
								t.Fatal("changed raw origin acquired numerical effects", mutation)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86RawVMOVWInitializedResultsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, load := range []bool{false, true} {
				for _, wide := range []bool{false, true} {
					for _, memory := range []bool{false, true} {
						asm, declaration := x86RawVMOVWResultFixture(
							fmt.Sprintf("Value%d", count), target.arch, load, wide, memory)
						source.WriteString(asm)
						declarations.WriteString(declaration)
						count++
					}
				}
			}
			if count != 8 {
				t.Fatal("incomplete raw VMOVW format inventory", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized raw GP/X/m16 result sequence", err)
					}
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

func TestX86RawVMOVWRequiresInputsWithoutResults(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, load := range []bool{false, true} {
			for _, wide := range []bool{false, true} {
				for _, memory := range []bool{false, true} {
					name := fmt.Sprintf("%s/load=%t/wide=%t/memory=%t", target.triple, load, wide, memory)
					t.Run(name, func(t *testing.T) {
						source := "TEXT Value(SB),4,$0-0\n" +
							x86RawDisplacementDirectives(rawVMOVW(load, wide, 1, 0, memory)) + "RET\n"
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", target.arch, target.triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("raw VMOVW borrowed implementation zeros or unknown addresses", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86RawVMOVWRetainsPointerAndValueBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, load := range []bool{false, true} {
			source, declaration := x86RawVMOVWResultFixture("Value", target.arch, load, false, true)
			move := "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			for name, bad := range map[string]string{
				"unknown pointer": strings.Replace(source, move+" p+0(FP),AX", "", 1),
				"numeric pointer": strings.Replace(source, move+" p+0(FP),AX", "MOVL $4096,AX", 1),
			} {
				t.Run(fmt.Sprintf("%s/load=%t/%s", target.triple, load, name), func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, bad, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw VMOVW invented incoming pointer identity", api, err)
						}
					}
				})
			}
		}
	}
}
