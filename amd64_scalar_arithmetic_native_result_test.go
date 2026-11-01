package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Keep this inventory independent of the production descriptors. These are
// all four widths of Go's add/subtract, carry/borrow and logical families.
var x86ScalarArithmeticNativeNames = []string{
	"ADDB", "ADDW", "ADDL", "ADDQ",
	"SUBB", "SUBW", "SUBL", "SUBQ",
	"ADCB", "ADCW", "ADCL", "ADCQ",
	"SBBB", "SBBW", "SBBL", "SBBQ",
	"ANDB", "ANDW", "ANDL", "ANDQ",
	"ORB", "ORW", "ORL", "ORQ",
	"XORB", "XORW", "XORL", "XORQ",
}

func TestX86ScalarArithmeticNativeSparseBytesFlagsAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86ScalarArithmeticNativeNames {
			width := map[byte]int64{'B': 1, 'W': 2, 'L': 4, 'Q': 8}[op[len(op)-1]]
			if arch == "386" && width == 8 {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" -1(DX)(BX*1),CX")
				base, _, _ := x86ResultGP(DX, 4, arch)
				index, _, _ := x86ResultGP(BX, 4, arch)
				destination, mask, _ := x86ResultGP(CX, width, arch)
				for seed := 0; seed < 256; seed++ {
					for flags := uint8(0); flags <= x86ByteFlagsAll; flags++ {
						state := x86ResultState{flags: flags}
						state.pointerGP[base], state.gp[index], state.gp[destination] = true, 0xff, uint8(seed)
						want := state.clone()
						accepted := uint8(seed)&mask == mask &&
							(!strings.HasPrefix(op, "ADC") && !strings.HasPrefix(op, "SBB") || flags&x86ByteFlagCF != 0)
						if accepted {
							want.flags = x86ByteFlagsAll
							if strings.HasPrefix(op, "AND") || strings.HasPrefix(op, "OR") || strings.HasPrefix(op, "XOR") {
								want.flags &^= x86ByteFlagAF // Logical AF is undefined, not preserved.
							}
							if width == 4 {
								want.gp[destination] = 0xff
							}
						}
						if got, known := x86LoweredScalarArithmeticNativeRead(ins, &state, nil, 0, arch); !known || got != accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("arithmetic changed byte/FLAGS roles", seed, flags, got, accepted, state, want)
						}
					}
				}
				for _, origin := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment", "pointer destination"} {
					changed := ins
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.pointerGP[base], state.gp[index], state.gp[destination] = true, 0xff, 0xff
					switch origin {
					case "decoded":
						changed.x86Encoded = true
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "raw return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					case "address":
						changed.x86AddressBits = 32
					case "unbound address":
						changed.x86UnboundAddressOverride = true
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "pointer destination":
						state.pointerGP[destination] = true
					}
					before := state.clone()
					if accepted, known := x86LoweredScalarArithmeticNativeRead(changed, &state, nil, 0, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("unbound origin acquired native arithmetic", origin, state)
					}
				}
			})
		}
	}
}

func TestX86ScalarArithmeticNativeOriginalREXByteAliases(t *testing.T) {
	for _, row := range []struct {
		op   string
		byte byte
	}{{"ADDB", 0x02}, {"SUBB", 0x2a}, {"ADCB", 0x12}, {"SBBB", 0x1a},
		{"ANDB", 0x22}, {"ORB", 0x0a}, {"XORB", 0x32}} {
		for ordinal, reg := range []string{"AH", "CH", "DH", "BH"} {
			for _, address := range []string{"(DX)", "(R8)", "(DX)(R9*2)"} {
				instruction := row.op + " " + address + "," + reg
				code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+instruction+"\nRET\n")
				want := []byte{row.byte, byte(0x22 + ordinal*8), 0xc3}
				effective := Reg(reg)
				if address == "(R8)" {
					want = []byte{0x41, row.byte, byte(0x20 + ordinal*8), 0xc3}
				} else if address == "(DX)(R9*2)" {
					want = []byte{0x42, row.byte, byte(0x24 + ordinal*8), 0x4a, 0xc3}
				}
				if address != "(DX)" {
					effective = []Reg{SP, BP, SI, DI}[ordinal]
				}
				if !reflect.DeepEqual(code, want) {
					t.Fatalf("original REX/ModRM view changed: %s: %x != %x", instruction, code, want)
				}
				ins := x86ScalarLaneInstruction(t, instruction)
				form, known, err := x86ScalarArithmeticNativeReadProperties(ins, "amd64")
				if !known || err != nil || form.destination.Reg != effective {
					t.Fatal("typed destination differs from actual Go encoding", instruction, form, err)
				}
				if address != "(DX)" && ordinal < 2 {
					c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.Value", Ret: Void}, nil)
					before := output.String()
					if _, _, err := c.evalScalarArithmeticSource(ins, I8); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
						t.Fatal("arithmetic manufactured a physical SP/BP alias", err)
					}
				}
			}
		}
	}
}

func TestX86ScalarArithmeticNativeResultsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, op := range x86ScalarArithmeticNativeNames {
				if target.arch == "386" && strings.HasSuffix(op, "Q") {
					goAssemblerOracleOutput(t, target.arch, "TEXT f(SB),4,$0-0\n"+op+" (DX),CX\nRET\n", "", false)
					continue
				}
				for _, address := range []string{"(DX)", "-1(DX)(BX*1)"} {
					body := "CMPL BX,BX\n" + op + " " + address + ",CX"
					asm, decl := x86ExtensionNativeFixture(fmt.Sprintf("F%d", count), target.arch, body, false)
					source.WriteString(asm)
					declarations.WriteString(strings.ReplaceAll(decl, "*[4]byte", "*[16]byte"))
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("native arithmetic lost its paired numerical continuation", api, err)
				}
				for _, optimized := range []bool{false, true} {
					text := ir
					if optimized {
						text = x86MulDivRoundOptimize(t, text)
					}
					if strings.Count(text, "load volatile i") != count {
						t.Fatal("native arithmetic lost its exact observable reads", api, optimized, count)
					}
					compileLLVMToObject(t, llc, target.triple, "arithmetic-native.ll", "arithmetic-native.o", text)
				}
			}
		})
	}
}

func TestX86ScalarArithmeticDeadNativeReadsSurviveOptimization(t *testing.T) {
	for _, op := range x86ScalarArithmeticNativeNames {
		t.Run(op, func(t *testing.T) {
			source, declaration := x86ExtensionNativeFixture("Value", "amd64", "CMPL BX,BX\n"+op+" (DX),CX", true)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			width := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[op[len(op)-1]]
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if strings.Count(text, fmt.Sprintf("load volatile i%d,", width)) != 1 {
						t.Errorf("%s dead native read must retain exactly %d bits", api, width)
					}
				}
			}
		})
	}
}

func TestX86ScalarArithmeticNativeRetainsPublicAndSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, op := range x86ScalarArithmeticNativeNames {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				body := fmt.Sprintf("%s p+0(FP),DX\nMOVL $0,CX\nCMPL CX,CX\n%s (DX),CX\nMOVL CX,ret0+%d(FP)\nRET", move, op, word)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *[16]byte) uint32", body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unpaired declaration check acquired native storage", err)
					}
				}
				for name, body := range map[string]string{
					"unknown base":       op + " (DI),CX",
					"numeric base":       "MOVL $42,DX\n" + op + " (DX),CX",
					"unknown index":      op + " (DX)(SI*1),CX",
					"pointer index":      op + " (DX)(DX*1),CX",
					"unknown result":     op + " (DX),DI\n" + move + " DI,CX",
					"pointer result":     op + " (DX),DX\n" + move + " DX,CX",
					"native store":       op + " CX,(DX)",
					"unknown store data": op + " DI,(DX)",
					"unknown store base": op + " CX,(DI)",
					"destroyed pointer":  "MOVL $42,DX\n" + op + " (DX),CX",
				} {
					t.Run(name, func(t *testing.T) {
						source, declaration := x86ExtensionNativeFixture("Value", arch, "CMPL BX,BX\n"+body, false)
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if name == "native store" {
								// The paired RMW consumer now models this complete
								// read/write. Preserve its exact former negative and
								// require independent missing-input controls above.
								if err != nil || ir == "" {
									t.Fatal("complete paired native RMW lost its inputs", api, err)
								}
								llc := findLLVM22Tool("llc")
								if llc == "" {
									t.Fatal("LLVM22 llc required")
								}
								for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
									if strings.Count(text, "load volatile") != 1 || strings.Count(text, "store volatile") != 1 {
										t.Fatal("native RMW lost its exact observable read/write", api)
									}
									compileLLVMToObject(t, llc, triple, "paired-rmw.ll", "paired-rmw.o", text)
								}
								continue
							}
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("native arithmetic acquired an unproved source effect", api, err)
							}
						}
					})
				}
			})
		}
	}
}
