package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86PrivatePOPNativeStoreExactBitsAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, wide := int(x86ResultPointerWord(arch)), "Q"
		if arch == "386" {
			wide = "L"
		}
		for _, width := range []struct {
			suffix string
			bytes  int
		}{{"W", 2}, {wide, word}} {
			t.Run(arch+"/"+width.suffix, func(t *testing.T) {
				push := x86ScalarLaneInstruction(t, "PUSH"+width.suffix+" AX")
				pop := x86ScalarLaneInstruction(t, "POP"+width.suffix+" -1(DX)(CX*2)")
				for missing := -1; missing < width.bytes; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
						valueStack: &x86ResultValueStack{id: true}}
					state.pointerGP[2] = true
					state.gp[0], state.gp[1] = 255, uint8(1)<<uint(word)-1
					if missing >= 0 {
						state.gp[0] &^= 1 << uint(missing)
					}
					if accepted, known := x86ResultValueStackStep(push, &state, nil, 0, arch); !accepted || !known {
						t.Fatal("private copy cannot invent but must retain unknown pushed bytes")
					}
					before := state.clone()
					accepted, known := x86LoweredStackNativeStore(pop, &state, nil, 0, arch)
					if !known || accepted != (missing == -1) {
						t.Fatal("native POP did not retain exact-byte requirements", missing, accepted, known)
					}
					if !accepted {
						if !reflect.DeepEqual(state, before) {
							t.Fatal("rejected native POP mutated reaching private state")
						}
						continue
					}
					want := before.clone()
					want.valueStack.bytes = want.valueStack.bytes[:0]
					want.valueStack.wordCells = 0
					if !reflect.DeepEqual(state, want) {
						t.Fatal("native POP changed facts beyond the independently popped private cell")
					}
					for _, mutation := range []string{"pointer", "index", "physical", "raw", "address", "segment", "native-return"} {
						input, changed := before.clone(), pop
						switch mutation {
						case "pointer":
							input.pointerGP[2] = false
						case "index":
							input.gp[1] >>= 1
						case "physical":
							changed.x86Encoded = true
						case "raw":
							changed.x86SourceRaw = new(x86SourceRawInstruction)
						case "address":
							changed.x86AddressBits = 32
						case "segment":
							changed.x86SegmentPrefix = 0x64
						case "native-return":
							changed.x86RawNearReturn = new(x86RawNearReturnForm)
						}
						original := input.clone()
						if accepted, _ := x86LoweredStackNativeStore(changed, &input, nil, 0, arch); accepted || !reflect.DeepEqual(input, original) {
							t.Fatal("native POP invented address/origin permission", mutation)
						}
					}
					standalone := before.clone()
					if accepted, _ := x86ResultValueStackStep(pop, &standalone, nil, 0, arch); accepted {
						t.Fatal("standalone numerical POP observer acquired native store permission")
					}
				}
			})
		}
	}
}

func TestX86PrivatePOPNativeStoresFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			move, typ, word, wide := "MOVQ", "uint64", 8, "Q"
			if target.arch == "386" {
				move, typ, word, wide = "MOVL", "uint32", 4, "L"
			}
			for _, width := range []struct {
				suffix string
				bytes  int
			}{{"W", 2}, {wide, word}} {
				t.Run(width.suffix, func(t *testing.T) {
					declaration := fmt.Sprintf("func Value(out *byte,value %s) %s\n", typ, typ)
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DX\nMOVL $1,CX\nPUSH%s value+%d(FP)\nPOP%s -1(DX)(CX*2)\nPUSH%s value+%d(FP)\nPOP%s -1(DX)(CX*2)\n%s value+%d(FP),AX\n%s AX,ret+%d(FP)\nRET\n",
						3*word, move, width.suffix, word, width.suffix, width.suffix, word, width.suffix, move, word, move, 2*word)
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("actual bounded private POP lost its native write continuation", err)
							}
							for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								if strings.Count(input, fmt.Sprintf("store volatile i%d ", width.bytes*8)) != 2 {
									t.Fatal("overwritten private POP stores lost exact observable width", width)
								}
								compileLLVMToObject(t, llc, target.triple, "private-pop-store.ll", "private-pop-store.o", input)
							}
						})
					}
					for name, changed := range map[string]string{
						"unknown stack bytes": strings.ReplaceAll(source, "PUSH"+width.suffix+" value+"+fmt.Sprint(word)+"(FP)", "PUSH"+width.suffix+" AX"),
						"unknown index":       strings.Replace(source, "MOVL $1,CX\n", "", 1),
						"unknown base":        strings.Replace(source, move+" out+0(FP),DX\n", "", 1),
						"unbalanced":          strings.Replace(source, "RET\n", "PUSH"+width.suffix+" $1\nRET\n", 1),
					} {
						t.Run(name, func(t *testing.T) {
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api)
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("private POP invented stack/address/balance facts", api, err)
								}
							}
						})
					}
				})
			}
		})
	}
}
