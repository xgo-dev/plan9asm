package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var x86BLSTestNames = []string{"BLSIL", "BLSIQ", "BLSMSKL", "BLSMSKQ", "BLSRL", "BLSRQ"}

func TestX86BLSTypedInputsAndDefinedFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86BLSTestNames {
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" AX,BX")
				effect, known, err := x86TypedGPByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 {
					t.Fatal("complete BLS family lacks its source/result effect", known, err)
				}
				width := int64(4)
				if arch == "amd64" && strings.HasSuffix(op, "Q") {
					width = 8
				}
				for ordinal, operand := range effect.operands {
					if operand.index != ordinal || !reflect.DeepEqual(operand.operand, ins.Args[ordinal]) ||
						operand.width != width || operand.read != (ordinal == 0) || operand.write != (ordinal == 1) {
						t.Fatal("BLS changed ordered inputs, result or physical-mode width", operand)
					}
				}
				defined := x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF
				if effect.flagsRead != 0 || effect.flagsDefined != defined || effect.flagsKilled != x86ByteFlagsAll ||
					!effect.requiresResultProof || effect.dynamicMemory {
					t.Fatal("BLS invented incoming, preserved or defined status bits", effect)
				}
			})
		}
	}
}

func TestX86BLSVoidNativeInputsCannotBypassWholeProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, unusedBool := range []bool{false, true} {
			word, move, declaration := int(goWordSize(target.arch)), "MOVQ", "func Value(p *[16]byte)"
			if word == 4 {
				move = "MOVL"
			}
			extent := word
			if unusedBool {
				declaration = "func Value(p *[16]byte, unused bool)"
				extent++
			}
			var original strings.Builder
			for ordinal, op := range x86BLSTestNames {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\n%s 3(AX)(DX*2),CX\nRET\n", extent, move, op)
				variants := []struct{ name, source string }{
					{"initialized", source},
					{"unknown-pointer", strings.Replace(source, move+" p+0(FP),AX", move+" p+0(FP),DI", 1)},
					{"numerical-pointer", strings.Replace(source, move+" p+0(FP),AX", "MOVL $1,AX", 1)},
					{"unknown-index", strings.Replace(source, "MOVL $1,DX\n", "", 1)},
				}
				for index, variant := range variants {
					name := fmt.Sprintf("Value%dCase%d", ordinal, index)
					original.WriteString(strings.Replace(variant.source, "·Value(SB)", "·"+name+"(SB)", 1))
				}
				t.Run(fmt.Sprintf("%s/bool%t/%s", target.triple, unusedBool, op), func(t *testing.T) {
					for _, variant := range variants {
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, variant.source, declaration, target.arch, target.triple, api)
							if variant.name == "initialized" {
								if err != nil || ir == "" {
									t.Fatal("complete Void BLS native inputs rejected", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Errorf("%s/%s: missing BLS native input bypassed the proof: %v", variant.name, api, err)
							}
						}
					}
				})
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, original.String())
		}
	}
}

func TestX86BLSInitializedPhysicalWidthsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete BLS objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		for _, op := range x86BLSTestNames {
			for _, memory := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/memory%t", target.triple, op, memory), func(t *testing.T) {
					width, typ, move := 4, "uint32", "MOVL"
					if target.arch == "amd64" && strings.HasSuffix(op, "Q") {
						width, typ, move = 8, "uint64", "MOVQ"
					}
					parameter, input, load, result := typ, "AX", move, width
					if target.arch == "amd64" {
						result = 8 // ABI0 result fields begin at the next native-word boundary.
					}
					if memory {
						parameter, input, result = "*"+typ, "(AX)", int(goWordSize(target.arch))
						load = "MOVL"
						if result == 8 {
							load = "MOVQ"
						}
					}
					declaration := fmt.Sprintf("func Value(source %s) %s", parameter, typ)
					body := fmt.Sprintf("%s source+0(FP),AX\n%s %s,DX\n%s DX,ret0+%d(FP)\nRET\n", load, op, input, move, result)
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("complete BLS typed source rejected", api, err)
						}
						for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							if memory && !strings.Contains(text, fmt.Sprintf("load volatile i%d, ptr", width*8)) {
								t.Fatal("BLS lost its exact native read", width)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					}
				})
			}
		}
	}
}
