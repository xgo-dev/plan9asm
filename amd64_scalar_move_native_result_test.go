package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ScalarMoveNativeOriginalHighByteEncodings(t *testing.T) {
	for ordinal, reg := range []string{"AH", "CH", "DH", "BH"} {
		for _, address := range []string{"(DX)", "(R8)", "(DX)(R9*2)"} {
			body := "TEXT native(SB),4,$0-0\nMOVB " + address + "," + reg + "\nRET\n"
			code := x86OrderingHintGoBytes(t, "amd64", body)
			want := []byte{0x8a, byte(0x22 + ordinal*8), 0xc3}
			if address == "(R8)" {
				want = []byte{0x41, 0x8a, byte(0x20 + ordinal*8), 0xc3}
			} else if address == "(DX)(R9*2)" {
				want = []byte{0x42, 0x8a, byte(0x24 + ordinal*8), 0x4a, 0xc3}
			}
			if !reflect.DeepEqual(code, want) {
				t.Fatalf("original Go high-byte encoding changed: %s %s = %x, want %x", address, reg, code, want)
			}
			ins := x86ScalarLaneInstruction(t, "MOVB "+address+","+reg)
			form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, "amd64")
			effective := Reg(reg)
			if address != "(DX)" {
				effective = []Reg{SP, BP, SI, DI}[ordinal]
			}
			if !known || err != nil || form.destination != effective || form.bytes != 1 {
				t.Fatal("typed native load differs from original ModRM/REX role", form, err)
			}
			if address != "(DX)" && ordinal < 2 {
				c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.Value", Ret: Void}, nil)
				before := output.String()
				if err := c.lowerScalarNativeLoad(form, ins); !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
					t.Fatal("REX alias manufactured a physical SP/BP write", err)
				}
			}
		}
	}
}

func TestX86ScalarMoveNativeByteEffectsAndOrigins(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			op    string
			width int
		}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}, {"MOVD", 8}} {
			if arch == "386" && row.width == 8 {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.op+" -1(DX)(BX*1),CX")
				base, _, _ := x86ResultGP(DX, 4, arch)
				index, _, _ := x86ResultGP(BX, 4, arch)
				destination, _, _ := x86ResultGP(CX, 4, arch)
				for seed := 0; seed < 256; seed++ {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.pointerGP[base] = true
					state.pointerGP[destination] = true
					state.gp[index] = 0xff
					state.gp[destination] = uint8(seed)
					want := state.clone()
					want.pointerGP[destination] = false
					mask := uint8(0xff)
					if row.width < 4 {
						mask = uint8(1<<row.width) - 1
					}
					want.gp[destination] |= mask
					if accepted, known := x86LoweredScalarNativeLoad(ins, &state, nil, 0, arch); !accepted || !known || !reflect.DeepEqual(state, want) {
						t.Fatal("scalar load changed byte/FLAGS/pointer roles", seed, state, want)
					}
				}
				for _, origin := range []string{"decoded", "raw", "raw return", "address", "unbound address", "segment"} {
					changed := ins
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
					}
					state := x86ResultState{}
					state.pointerGP[base], state.gp[index] = true, 0xff
					before := state.clone()
					if accepted, _ := x86LoweredScalarNativeLoad(changed, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("native load acquired an unbound origin", origin, state)
					}
				}
			})
		}
	}
}

func TestX86ScalarMoveNativeRejectsMalformedAddressesBeforeIR(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ", "MOVD"} {
		t.Run(op, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+op+" 8(BAD),AX\nRET\n", "", false)
			ins := Instr{Op: Op(op), Raw: op + " 8(BAD),AX", Args: []Operand{
				{Kind: OpMem, Mem: MemRef{Base: "BAD", Off: 8}}, {Kind: OpReg, Reg: AX},
			}}
			c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.Value", Ret: Void}, nil)
			before := output.String()
			if handled, _, err := c.lowerMov(ins.Op, ins); !handled || err == nil || output.String() != before {
				t.Fatal("malformed address created a zero/native read", handled, err)
			}
		})
	}
}

func TestX86ScalarMoveNativeKeepsNamedAddressRolesSeparate(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVW", "MOVL"} {
		for _, address := range []string{"table<>(SB)(R8)", "table<>(SB)(SP)", "table<>(SB)(AX)(CX*2)"} {
			instruction := op + " " + address + ",AX"
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n", "", true)
			ins := x86ScalarLaneInstruction(t, instruction)
			if _, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, "386"); known || err != nil {
				t.Fatal("register-addressed read consumed Go's distinct SB address role", instruction, err)
			}
		}
	}
}

func TestX86ScalarMoveNativeRetainsPublicAndSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ", "MOVD"} {
			if arch == "386" && (op == "MOVQ" || op == "MOVD") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				body := fmt.Sprintf("%s p+0(FP),DX\nMOVL $0,CX\n%s (DX),CX\nMOVL CX,ret0+%d(FP)\nRET", move, op, word)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *[16]byte) uint32", body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("standalone query acquired native storage", err)
					}
				}
				t.Run("paired-native-load-and-store", func(t *testing.T) {
					// Retain the original complete source. This is now the
					// independently paired NUM store, not a load-only grant.
					source, declaration := x86ExtensionNativeFixture("Value", arch, op+" (DX),CX\n"+op+" CX,(DX)", false)
					goAssemblerOracleOutput(t, arch, source, "", true)
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM22 llc required")
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil || ir == "" || !strings.Contains(ir, "load volatile ") || !strings.Contains(ir, "store volatile ") {
							t.Fatal("paired load/store lost a complete native effect", api, err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, ir, level)
						}
					}
				})
				for name, body := range map[string]string{
					"unknown base":       op + " (DI),CX",
					"numeric base":       "MOVL $42,DX\n" + op + " (DX),CX",
					"unknown index":      op + " (DX)(SI*1),CX",
					"pointer index":      op + " (DX)(DX*1),CX",
					"pointer destroyed":  op + " (DX),DX\nMOVB (DX),CX",
					"unbound store":      op + " (DX),CX\n" + op + " CX,(SI)",
					"mixed pointer join": "CMPL BX,$0\nJE other\n" + move + " DX,DI\nJMP end\nother:\nMOVL $42,DI\nend:\n" + op + " (DI),CX",
				} {
					t.Run(name, func(t *testing.T) {
						source, declaration := x86ExtensionNativeFixture("Value", arch, body, false)
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("native continuation widened its source contract", api, err)
							}
						}
					})
				}
			})
		}
	}
}

// The original sing-tun checksum counterexample reaches an ordinary scalar
// load before VPEXTRQ consumes the result proof. Reproduce that whole class
// without importing or compiling the external library.
func TestX86ScalarMoveNativeResultsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for _, op := range []string{"MOVB", "MOVW", "MOVL", "MOVQ", "MOVD"} {
				if target.arch == "386" && (op == "MOVQ" || op == "MOVD") {
					goAssemblerOracleOutput(t, target.arch, "TEXT f(SB),4,$0-0\n"+op+" (DX),CX\nRET\n", "", false)
					continue
				}
				for _, address := range []string{"(DX)", "-1(DX)(BX*1)"} {
					body, decl := x86ExtensionNativeFixture(fmt.Sprintf("Value%d", count), target.arch, op+" "+address+",CX", false)
					source.WriteString(body)
					declarations.WriteString(strings.ReplaceAll(decl, "*[4]byte", "*[16]byte"))
					count++
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("ordinary native MOV lost its paired numerical continuation", err)
					}
					if strings.Count(ir, "load volatile i") != count {
						t.Fatal("ordinary native MOV lacks its exact observable read", count)
					}
					for _, optimized := range []bool{false, true} {
						text := ir
						if optimized {
							text = x86MulDivRoundOptimize(t, text)
						}
						stem := fmt.Sprintf("scalar-move-native-%t", optimized)
						compileLLVMToObject(t, llc, target.triple, stem+".ll", stem+".o", text)
					}
				})
			}
		})
	}
}

func TestX86ScalarMoveDeadNativeReadSurvivesOptimization(t *testing.T) {
	for _, row := range []struct {
		op    string
		width int
	}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}, {"MOVD", 8}} {
		t.Run(row.op, func(t *testing.T) {
			source, decl := x86ExtensionNativeFixture("Value", "amd64", row.op+" (DX),CX", true)
			decl = strings.ReplaceAll(decl, "*[4]byte", "*[16]byte")
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, decl, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprintf("load volatile i%d,", row.width*8)
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					if strings.Count(text, want) != 1 {
						t.Errorf("%s dead %s lost its exact native read", api, row.op)
					}
				}
			}
		})
	}
}
