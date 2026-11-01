package plan9asm

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ByteSwapCompleteOfficialGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	table := string(data)
	if !strings.Contains(table, "var ybswap = []ytab{\n\t{Z_rp, 2, argList{Yrl}},\n}") {
		t.Fatal("complete official Go BSWAP classes/zcase/zoffset changed")
	}
	rows := regexp.MustCompile(`\{A(BSWAP\w+), (\w+), (\w+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(table, -1)
	if len(rows) != 2 || len(x86ByteSwapSpecs) != 2 {
		t.Fatal("complete BSWAP family changed", rows)
	}
	for _, row := range rows {
		prefix := map[string]string{"BSWAPL": "Px", "BSWAPQ": "Pw"}[row[1]]
		if prefix == "" || row[2] != "ybswap" || row[3] != prefix || row[4] != "0x0f, 0xc8" {
			t.Fatal("complete BSWAP opcode/operand-size attributes changed", row)
		}
	}
}

func TestX86ByteSwapCompleteGrammarAndDescriptor(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []Op{"BSWAPL", "BSWAPQ"} {
			for _, register := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH X0 Y0 Z0 K1 M0 FS TLS R16") {
				t.Run(arch+"/"+string(op)+"/"+register, func(t *testing.T) {
					ins := Instr{Op: op, Args: []Operand{{Kind: OpReg, Reg: Reg(register)}}, Raw: string(op) + " " + register}
					before := ins
					before.Args = append([]Operand(nil), ins.Args...)
					valid := strings.Contains(" AX CX DX BX SP BP SI DI ", " "+register+" ") ||
						arch == "amd64" && strings.Contains(" R8 R9 R10 R11 R12 R13 R14 R15 ", " "+register+" ")
					valid = valid && !(arch == "386" && op == "BSWAPQ")
					effect, known, err := x86TypedInstructionByteEffect(op, ins, arch)
					if !known || (err == nil) != valid {
						t.Fatal("Go grammar bank/mode mismatch", known, err, valid)
					}
					if !reflect.DeepEqual(before, ins) {
						t.Fatal("descriptor rewrote original instruction")
					}
					if valid {
						width := int64(4)
						if op == "BSWAPQ" {
							width = 8
						}
						want := x86TypedByteEffect{operands: []x86TypedByteOperand{{index: 0, operand: ins.Args[0], width: width, read: true, write: true}}}
						if !reflect.DeepEqual(effect, want) {
							t.Fatal("BSWAP gained flags/memory/other operand effects", effect)
						}
					}
				})
			}
			for _, args := range [][]Operand{nil, {{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}},
				{{Kind: OpImm, Imm: 7}}, {{Kind: OpFP, FPName: "ret", FPOffset: 0}},
				{{Kind: OpMem, Mem: MemRef{Base: AX}}}, {{Kind: OpSym, Sym: "table(SB)"}}} {
				if _, known, err := x86ByteSwapProperties(op, Instr{Op: op, Args: args}, arch); !known || err == nil {
					t.Fatal("unregistered BSWAP operand form accepted", arch, op, args)
				}
			}
		}
	}
	for _, op := range []Op{"BSWAPL.Z", "BSWAPQ.SAE"} {
		if _, known, err := x86ByteSwapProperties(op, Instr{Op: op, Args: []Operand{{Kind: OpReg, Reg: AX}}}, "amd64"); !known || err == nil {
			t.Fatal("unregistered suffix accepted", op)
		}
	}
	for _, op := range []Op{"BSWAP", "BSWAPB", "BSWAPW", "BSWAPX"} {
		if _, known, err := x86ByteSwapProperties(op, Instr{Op: op}, "amd64"); known || err != nil {
			t.Fatal("unregistered family name borrowed BSWAP", op)
		}
	}
	for _, arch := range []string{"arm", "arm64", "wasm", ""} {
		if _, known, err := x86ByteSwapProperties("BSWAPL", Instr{Args: []Operand{{Kind: OpReg, Reg: AX}}}, arch); !known || err == nil {
			t.Fatal("unbound/non-x86 mode acquired BSWAP", arch)
		}
	}
	if _, _, err := x86ByteSwapProperties("BSWAPL", Instr{Op: "BSWAPQ", Args: []Operand{{Kind: OpReg, Reg: AX}}}, "amd64"); err == nil {
		t.Fatal("dispatch/source opcode mismatch accepted")
	}
}

func TestX86ResultByteSwapEveryByteMaskAndIndependentFlags(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []Op{"BSWAPL", "BSWAPQ"} {
			if arch == "386" && op == "BSWAPQ" {
				continue // Independently rejected syntax row, not a skipped execution.
			}
			for _, register := range strings.Fields("AX CX DX BX SI DI BP R8 R9 R10 R11 R12 R13 R14 R15") {
				if arch == "386" && strings.HasPrefix(register, "R") {
					continue
				}
				if arch == "amd64" && register == "BP" {
					continue // Its independent physical frame role stays unbound.
				}
				t.Run(arch+"/"+string(op)+"/"+register, func(t *testing.T) {
					width := int64(4)
					if op == "BSWAPQ" {
						width = 8
					}
					root, _, valid := x86ResultGP(Reg(register), width, arch)
					if !valid {
						t.Fatal("ordinary typed bank unexpectedly unbound")
					}
					ins := Instr{Op: op, Args: []Operand{{Kind: OpReg, Reg: Reg(register)}}}
					for mask := 0; mask < 256; mask++ {
						state := x86ResultState{flags: uint8(mask) & x86ByteFlagsAll, direction: x86ResultDirection(mask % 4)}
						state.gp[root] = uint8(mask)
						state.pointerGP[root] = true
						before := state.clone()
						if !x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("pure byte permutation rejected", mask)
						}
						want := bits.Reverse8(uint8(mask))
						if width == 4 {
							want = bits.Reverse8(uint8(mask)&15)>>4 | 0xf0
						}
						before.gp[root], before.pointerGP[root] = want, false
						if !reflect.DeepEqual(before, state) {
							t.Fatal("byte dependency/zero-extension/unchanged state mismatch", mask, want, state)
						}
					}
				})
			}
		}
	}
}

func TestX86ResultByteSwapCanonicalAndAddressDomains(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		op, width := Op("BSWAPQ"), int64(8)
		if arch == "386" {
			op, width = "BSWAPL", 4
		}
		ins := Instr{Op: op, Args: []Operand{{Kind: OpReg, Reg: CX}}}
		before := [16]bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true}
		after := x86ResultCallerAddressesAfter(ins, before, nil, arch)
		before[1] = false
		if after != before {
			t.Fatal("BSWAP preserved rewritten caller address or revoked unrelated GP", arch, after)
		}
		for mask := 0; mask < 256; mask++ {
			var canonical [16]uint8
			canonical[1], canonical[3] = uint8(mask), 0xa5
			got := x86RegisterCanonicalBytesAfter(ins, canonical, arch)
			want := bits.Reverse8(uint8(mask))
			if width == 4 {
				want = bits.Reverse8(uint8(mask)&15)>>4 | uint8(mask)&0xf0
			}
			canonical[1] = want
			if got != canonical {
				t.Fatal("canonical bytes did not follow their actual permutation", arch, mask, got, canonical)
			}
		}
	}
}

func TestX86ByteSwapLowererUsesCompleteGrammarWithoutStatusWrites(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []Op{"BSWAPL", "BSWAPQ"} {
			for _, reg := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH X0 K1") {
				ins := Instr{Op: op, Args: []Operand{{Kind: OpReg, Reg: Reg(reg)}}}
				c, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
				c.goarch = arch
				start := output.Len()
				_, _, grammarError := x86ByteSwapProperties(op, ins, arch)
				handled, terminal, err := c.lowerArith(op, ins)
				if grammarError == nil && arch == "386" && reg == "SP" {
					if !handled || terminal || err == nil || !strings.Contains(err.Error(), "386 direct SP write is unsupported") {
						t.Fatal("valid Go SP syntax bypassed its independent stack-write contract", err)
					}
					continue
				}
				if !handled || terminal || (err == nil) != (grammarError == nil) {
					t.Fatal("lowerer diverged from shared complete grammar", arch, op, reg, handled, terminal, err)
				}
				added := output.String()[start:]
				if err != nil {
					if added != "" {
						t.Fatal("invalid BSWAP emitted partial IR", added)
					}
					continue
				}
				bits := 32
				if op == "BSWAPQ" {
					bits = 64
				}
				if !strings.Contains(added, fmt.Sprintf("call i%d @llvm.bswap.i%d", bits, bits)) || strings.Contains(added, "store i1") {
					t.Fatal("wrong byte-swap width or status/DF write", added)
				}
			}
		}
	}
}

func TestX86ResultByteSwapCompleteThreeAPITypedBanks(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, op := range []string{"BSWAPL", "BSWAPQ"} {
			if target.arch == "386" && op == "BSWAPQ" {
				continue
			}
			for _, reg := range strings.Fields("AX CX DX BX SI DI BP R8 R9 R10 R11 R12 R13 R14 R15") {
				if target.arch == "386" && strings.HasPrefix(reg, "R") {
					continue
				}
				if target.arch == "amd64" && reg == "BP" {
					continue
				}
				move, typ := "MOVL", "uint32"
				if op == "BSWAPQ" {
					move, typ = "MOVQ", "uint64"
				}
				_, _, _, source := x86ResultInitializationFixture(t, target.arch, "func Value(x "+typ+") "+typ,
					fmt.Sprintf("%s x+0(FP),%s\n%s %s\n%s %s,ret0+%d(FP)\nRET", move, reg, op, reg, move, reg, goWordSize(target.arch)))
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+reg+"/"+api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value(x "+typ+") "+typ+"\n", target.arch, target.triple)
						if err != nil || ir == "" {
							t.Fatal("actual initialized ABI0 result lost its BSWAP bytes", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ResultByteSwapPhysicalStackAndFrameStayIndependent(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, register := range []Reg{SP, BP} {
			if arch == "386" && register == BP {
				continue // Positive source-defined BP is in the complete bank roots.
			}
			op, move, typ, word := "BSWAPQ", "MOVQ", "uint64", 8
			if arch == "386" {
				op, move, typ, word = "BSWAPL", "MOVL", "uint32", 4
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+string(register)+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s $7,%s\n%s %s\n%s %s,ret0+0(FP)\nRET\n", word, move, register, op, register, move, register)
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() "+typ+"\n", arch, testTargetTriple("linux", arch))
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("numerical byte swap acquired a physical SP/AMD64 BP contract", err)
					}
				})
			}
		}
	}
}

func TestX86ResultByteSwapCanonicalBoolAndRawSeparation(t *testing.T) {
	for _, value := range []uint32{0, 0x01000000, 0x02000000, 0xff000000} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("386/%x/%s", value, api), func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nMOVL $%d,AX\nBSWAPL AX\nMOVB AX,ret0+0(FP)\nRET\n", value)
				ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() bool\n", "386", "i386-unknown-linux-gnu")
				if value <= 0x01000000 {
					if err != nil || ir == "" {
						t.Fatal("permuted actual canonical byte rejected", err)
					}
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("numerical definedness became canonical bool", err)
				}
			})
		}
	}
	for _, mutate := range []func(*Instr){
		func(ins *Instr) { ins.x86Encoded = true },
		func(ins *Instr) { ins.x86AddressBits = 32 },
		func(ins *Instr) { ins.x86UnboundAddressOverride = true },
		func(ins *Instr) { ins.x86SegmentPrefix = 1 },
	} {
		ins := Instr{Op: "BSWAPL", Args: []Operand{{Kind: OpReg, Reg: AX}}}
		mutate(&ins)
		state := x86ResultState{}
		state.gp[0] = 255
		before := state.clone()
		if x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(before, state) {
			t.Fatal("physical/raw role borrowed ordinary BSWAP byte proof", ins)
		}
	}
}

func TestX86ResultByteSwapCFGPartialAndOpaqueBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		op, move, typ, word := "BSWAPQ", "MOVQ", "uint64", 8
		if arch == "386" {
			op, move, typ, word = "BSWAPL", "MOVL", "uint32", 4
		}
		for _, row := range []struct {
			name, declaration, body string
			accept                  bool
		}{
			{"partial double permutation", "func Value() uint8", "MOVB $7,AX\n" + op + " AX\n" + op + " AX\nMOVB AX,ret0+0(FP)", true},
			{"partial byte moves away", "func Value() uint8", "MOVB $7,AX\n" + op + " AX\nMOVB AX,ret0+0(FP)", false},
			{"partial full result", "func Value() " + typ, "MOVB $7,AX\n" + op + " AX\n" + move + " AX,ret0+0(FP)", false},
			{"both CFG paths initialize", "func Value(x " + typ + ") " + typ, move + " x+0(FP),BX\nCMP" + string(move[len(move)-1]) + " BX,$0\nJE other\n" + move + " $7,AX\nJMP joined\nother:\n" + move + " $9,AX\njoined:\n" + op + " AX\n" + move + fmt.Sprintf(" AX,ret0+%d(FP)", word), true},
			{"unknown CFG path", "func Value(x " + typ + ") " + typ, move + " x+0(FP),BX\nCMP" + string(move[len(move)-1]) + " BX,$0\nJE joined\n" + move + " $7,AX\njoined:\n" + op + " AX\n" + move + fmt.Sprintf(" AX,ret0+%d(FP)", word), false},
			{"pointer double permutation not numeric", "func Value(p *byte) " + typ, move + " p+0(FP),AX\n" + op + " AX\n" + op + " AX\n" + move + fmt.Sprintf(" AX,ret0+%d(FP)", word), false},
			{"unknown flags remain unknown", "func Value() uint8", move + " $7,AX\n" + op + " AX\nSETEQ ret0+0(FP)", false},
			{"known flags unchanged", "func Value() uint8", move + " $7,AX\nCMP" + string(move[len(move)-1]) + " AX,$0\n" + op + " AX\nSETEQ ret0+0(FP)", true},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, row.declaration, row.body+"\nRET")
				err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
				if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("full CFG byte/opaque/flags boundary differs", row.accept, err)
				}
			})
		}
	}
}

func TestX86ResultByteSwapWholeSource(t *testing.T) {
	for _, row := range []struct{ arch, op, move, typ string }{
		{"amd64", "BSWAPQ", "MOVQ", "uint64"},
		{"amd64", "BSWAPL", "MOVL", "uint32"},
		{"386", "BSWAPL", "MOVL", "uint32"},
	} {
		t.Run(row.arch+"/"+row.op, func(t *testing.T) {
			body := fmt.Sprintf("%s x+0(FP),AX\n%s AX\n%s AX,ret0+%d(FP)\nRET", row.move, row.op, row.move, goWordSize(row.arch))
			_, file, sig, _ := x86ResultInitializationFixture(t, row.arch, "func Value(x "+row.typ+") "+row.typ, body)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, row.arch); err != nil {
				t.Fatal("initialized numerical BSWAP lost its complete result:", err)
			}
		})
	}
}

func TestX86ResultByteSwapUnknownPublicResult(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				op, move, typ, bytes := "BSWAPQ", "MOVQ", "uint64", 8
				if target.arch == "386" {
					op, move, typ, bytes = "BSWAPL", "MOVL", "uint32", 4
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s AX\n%s AX,ret0+0(FP)\nRET\n", bytes, op, move)
				ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() "+typ+"\n", target.arch, target.triple)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unknown BSWAP bytes became a declared result: output=%t error=%v", ir != "", err)
				}
			})
		}
	}
}

func TestX86ResultByteSwapLogicalBoolRequiresIndependentRole(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("canonical BSWAP objects require LLVM22 llc")
	}
	for _, target := range x86OrderingHintTargets {
		for _, op := range []string{"BSWAPL", "BSWAPQ"} {
			if target.arch == "386" && op == "BSWAPQ" {
				continue
			}
			for _, row := range []struct {
				name, initialize string
				accept           bool
			}{
				{"unknown", "", false},
				{"noncanonical", "MOVL $0x02000000,AX\n", false},
				{"canonical zero", "MOVL $0,AX\n", true},
				{"canonical one", "MOVL $0x01000000,AX\n", true},
			} {
				initialize := row.initialize
				if op == "BSWAPQ" {
					switch row.name {
					case "noncanonical":
						initialize = "MOVQ $0x0200000000000000,AX\n"
					case "canonical one":
						initialize = "MOVQ $0x0100000000000000,AX\n"
					}
				}
				source := "TEXT ·Value(SB),4,$0-1\n" + initialize + op + " AX\nMOVB AX,ret0+0(FP)\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+row.name+"/"+api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() bool\n", target.arch, target.triple)
						if !row.accept {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("undefined/noncanonical BSWAP bytes became a logical bool: output=%t error=%v", ir != "", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("canonical byte permutation lost its ordinary ABI0 bool role", err)
						}
						for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					})
				}
			}
		}
		for _, value := range []int{0, 1} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/unchanged-bool/%d/%s", target.triple, value, api), func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nMOVB $%d,ret0+0(FP)\nRET\n", value)
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() bool\n", target.arch, target.triple)
					if err != nil || ir == "" {
						t.Fatal("BSWAP admission stole an unchanged independent bool body", err)
					}
				})
			}
		}
	}
}

func TestX86ResultByteSwapUnknownNonIntegerResults(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, row := range []struct {
			typ, move string
			width     int
		}{
			{"float32", "MOVL", 4}, {"float64", "MOVQ", 8}, {"*byte", "MOVQ", 8},
		} {
			op := "BSWAPQ"
			if target.arch == "386" {
				op = "BSWAPL"
				if row.typ == "*byte" {
					row.move, row.width = "MOVL", 4
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.typ+"/"+api, func(t *testing.T) {
					store := row.move + " AX,ret0+0(FP)\n"
					if target.arch == "386" && row.typ == "float64" {
						store = "MOVL AX,ret0+0(FP)\nMOVL AX,ret0+4(FP)\n"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s AX\n%sRET\n", row.width, op, store)
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() "+row.typ+"\n", target.arch, target.triple)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unknown BSWAP bits escaped through a noninteger result: output=%t error=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestX86ResultByteSwapExistingRegisterBoolRole(t *testing.T) {
	for _, op := range []string{"BSWAPL", "BSWAPQ"} {
		for _, value := range []uint64{0, 1, 2, 255} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%d/%s", op, value, api), func(t *testing.T) {
					initialize := fmt.Sprintf("MOVL $%d,AX", value<<24)
					if op == "BSWAPQ" {
						initialize = fmt.Sprintf("MOVQ $%d,AX", value<<56)
					}
					source := amd64RegisterBoolSource(initialize + "\n" + op + " AX")
					ir, err := x86ScalarFPBitViewAPI(t, source, "func view(a,b uint64) bool\n", "amd64", "x86_64-unknown-linux-gnu", api)
					if value <= 1 {
						if err != nil || ir == "" {
							t.Fatal("existing actual register canonical role lost its BSWAP byte", err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("defined numerical byte became register canonical bool", err)
					}
				})
			}
		}
	}
}

func TestX86ResultByteSwapActualGoRegisterAliasKeepsSourceAndUnknownEntry(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		if target.arch != "amd64" {
			continue // Go registers g only on amd64; the actual assembler rejects386 above.
		}
		for _, op := range []string{"BSWAPL", "BSWAPQ"} {
			for _, initialized := range []bool{false, true} {
				body := op + " g\nMOVQ g,ret0+0(FP)\nRET\n"
				if initialized {
					body = "MOVQ $0x1122334455667788,g\n" + body
				}
				source := "TEXT ·Value(SB),4,$0-8\n" + body
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, ins := range file.Funcs[0].Instrs {
					if ins.Op == Op(op) {
						found = len(ins.Args) == 1 && ins.Args[0].Kind == OpReg && ins.Args[0].Reg == "R14" && ins.Raw == op+" g"
					}
				}
				if !found {
					t.Fatal("actual parsed alias lost original Op/Raw or normalized physical operand")
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/initialized=%t/%s", target.triple, op, initialized, api), func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value() uint64\n", target.arch, target.triple)
						if initialized {
							if err != nil || ir == "" {
								t.Fatal("source-defined ordinary numerical R14 alias lost its bytes", err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("g spelling supplied an invented thread/register entry value", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ResultByteSwapMixedBoolResultNeedsIndependentCanonicalRole(t *testing.T) {
	for _, target := range x86OrderingHintTargets {
		for _, op := range []string{"BSWAPL", "BSWAPQ"} {
			if target.arch == "386" && op == "BSWAPQ" {
				continue
			}
			for _, other := range []string{"uint8", "uint16", "uint32", "uint64", "float32", "float64"} {
				for _, boolFirst := range []bool{false, true} {
					results := other + ",bool"
					if boolFirst {
						results = "bool," + other
					}
					declaration := "func Value() (" + results + ")"
					_, _, sig, _ := x86ResultInitializationFixture(t, target.arch, declaration, "RET")
					var body strings.Builder
					initialize := "MOVL $0x02000000,AX\n"
					if op == "BSWAPQ" {
						initialize = "MOVQ $0x0200000000000000,AX\n"
					}
					body.WriteString(initialize + op + " AX\n")
					for index, slot := range sig.Frame.Results {
						if slot.Type == I1 {
							fmt.Fprintf(&body, "MOVB AX,ret%d+%d(FP)\n", index, slot.Offset)
							continue
						}
						width := x86FrameScalarBytes(slot.Type, target.arch)
						if width == 8 && target.arch == "386" {
							fmt.Fprintf(&body, "MOVL $0,ret%d+%d(FP)\nMOVL $0,ret%d+%d(FP)\n", index, slot.Offset, index, slot.Offset+4)
						} else {
							move := map[int64]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[width]
							if move == "" {
								t.Fatal("mixed result fixture lost its actual scalar field")
							}
							fmt.Fprintf(&body, "%s $0,ret%d+%d(FP)\n", move, index, slot.Offset)
						}
					}
					_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body.String()+"RET")
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+op+"/"+results+"/"+api, func(t *testing.T) {
							ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+declaration+"\n", target.arch, target.triple)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("initialized mixed result byte became canonical bool: output=%t error=%v", ir != "", err)
							}
						})
					}
				}
			}
		}
	}
}
