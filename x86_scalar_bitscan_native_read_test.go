package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ScalarBitScanNativeReadPreservesExactByteKnowledge(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, family := range []string{"BSF", "BSR"} {
			for _, suffix := range []string{"W", "L", "Q"} {
				if arch == "386" && suffix == "Q" {
					continue
				}
				t.Run(arch+"/"+family+suffix, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, family+suffix+" 0(SI),BX")
					seed := func(prior uint8) x86ResultState {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[3], state.pointerGP[6] = prior, true
						return state
					}
					for prior := 0; prior < 256; prior++ {
						state := seed(uint8(prior))
						if accepted, known := x86ResultBitScanStepWithRead(ins, &state, nil, arch, true); !accepted || !known || state.gp[3] != uint8(prior) || state.flags != x86ByteFlagZF {
							t.Fatal("native read invented zero-input destination or nonportable flags", prior, state)
						}
						if x86ResultRead(ins.Args[0], 1, &state, nil, arch) {
							t.Fatal("paired input created reusable numerical memory")
						}
						state = seed(uint8(prior))
						before := state.clone()
						if accepted, known := x86ResultBitScanStep(ins, &state, nil, arch); accepted || !known || !reflect.DeepEqual(state, before) {
							t.Fatal("standalone observer acquired a paired native read")
						}
					}
					for _, change := range []string{"missing address", "raw", "encoded", "near return", "address size", "segment"} {
						changed, state := ins, seed(0xff)
						switch change {
						case "missing address":
							state.pointerGP[6] = false
						case "raw":
							changed.x86SourceRaw = new(x86SourceRawInstruction)
						case "encoded":
							changed.x86Encoded = true
						case "near return":
							changed.x86RawNearReturn = new(x86RawNearReturnForm)
						case "address size":
							changed.x86AddressBits = 32
						case "segment":
							changed.x86SegmentPrefix = 0x64
						}
						before := state.clone()
						if accepted, known := x86ResultBitScanStepWithRead(changed, &state, nil, arch, true); accepted || !known || !reflect.DeepEqual(state, before) {
							t.Fatal("unbound or another source role acquired a paired read", change)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarBitScanPairedNativeReadWholeFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for _, family := range []string{"BSF", "BSR"} {
				for _, suffix := range []string{"W", "L", "Q"} {
					if target.arch == "386" && suffix == "Q" {
						continue
					}
					for _, dead := range []bool{false, true} {
						name := fmt.Sprint("NativeScan", len(names))
						names = append(names, name)
						body, declaration := x86ScalarRMRegisterInitializedFunction(name, family+suffix+" 0(SI),BX", target.arch)
						if dead {
							move := "Q"
							if target.arch == "386" {
								move = "L"
							}
							body = strings.Replace(body, "\nMOV"+move+" BX,ret+", "\nMOVL $7,BX\nMOV"+move+" BX,ret+", 1)
						}
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete native scan family lost its source continuation", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86CompactExpandRequireAllDefinitions(t, text, names)
						if strings.Count(text, "load volatile") != len(names) {
							t.Fatal("live or dead scan lost its exact observable read width")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
						for _, bits := range []int{16, 32, 64} {
							if bits == 64 && target.arch == "386" {
								continue
							}
							if !strings.Contains(text, fmt.Sprint("load volatile <", bits/8, " x i8>")) {
								t.Fatal("source width was replaced by the GP carrier", bits)
							}
						}
					}
				})
			}
		})
	}
}

func TestX86ScalarBitScanPairedReadRetainsProofBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, suffix := goWordSize(target.arch), "Q"
		if word == 4 {
			suffix = "L"
		}
		for _, family := range []string{"BSF", "BSR"} {
			for _, width := range []string{"W", "L", "Q"} {
				if target.arch == "386" && width == "Q" {
					continue
				}
				t.Run(target.triple+"/"+family+width, func(t *testing.T) {
					source, declaration := x86ScalarRMRegisterInitializedFunction("Value", family+width+" 0(SI),BX", target.arch)
					body := source[strings.Index(source, "\n")+1:]
					_, file, sig, _ := x86ResultInitializationFixture(t, target.arch, declaration, body)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone query acquired a native read", err)
					}
					for _, removed := range []string{
						"MOV" + suffix + " memory+0(FP),SI\n",
						fmt.Sprintf("MOV%s old+%d(FP),BX\n", suffix, word),
					} {
						changed := strings.Replace(source, removed, "", 1)
						if changed == source {
							t.Fatal("missing-input control changed no original instruction")
						}
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("scan invented an address or zero-input prior result", api, removed, err)
							}
						}
					}
					for _, foreign := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, foreign, "module"); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native scan acquired a foreign or missing backend", foreign, err)
						}
					}
					instruction := family + width + " 0(SI),BX"
					raw := x86RawNumericalInstruction(t, target.arch, instruction)
					changed := strings.Replace(source, instruction, raw, 1)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw scan borrowed the named native continuation", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarBitScanVoidStillRequiresSourceInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, suffix, triple := goWordSize(arch), "Q", "x86_64-unknown-linux-gnu"
		if word == 4 {
			suffix, triple = "L", "i386-unknown-linux-gnu"
		}
		for _, family := range []string{"BSF", "BSR"} {
			for _, width := range []string{"W", "L", "Q"} {
				if arch == "386" && width == "Q" {
					continue
				}
				for _, operand := range []string{"CX", "0(SI)"} {
					for _, unused := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s%s/%s/bool-%t", arch, family, width, operand, unused), func(t *testing.T) {
							operation := family + width + " " + operand + ",BX"
							source, _ := x86ScalarRMRegisterInitializedFunction("Value", operation, arch)
							body := source[strings.Index(source, "\n")+1:]
							body = strings.Replace(body, fmt.Sprintf("MOV%s BX,ret+%d(FP)\n", suffix, 3*word), "", 1)
							declaration, size := "func Value(memory *[8]byte,old,input uintptr)", 3*word
							if unused {
								declaration = "func Value(memory *[8]byte,old,input uintptr,unused bool)"
								size++
							}
							source = fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", size, body)
							removed := fmt.Sprintf("MOV%s input+%d(FP),CX\nCMPL CX,CX\n", suffix, 2*word)
							if operand == "0(SI)" {
								removed = "MOV" + suffix + " memory+0(FP),SI\n"
							}
							changed := strings.Replace(source, removed, "", 1)
							if changed == source {
								t.Fatal("input control did not alter the original source")
							}
							for _, api := range []string{"text", "module", "Go"} {
								if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); ir == "" || err != nil {
									t.Fatal("complete Void scan lost its initialized inputs", api, err)
								}
								if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("dead scan invented a numerical input or native address", api, err)
								}
							}
						})
					}
				}
			}
		}
	}
}
