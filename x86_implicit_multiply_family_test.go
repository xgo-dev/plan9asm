package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ImplicitMultiplyCompleteOfficialGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, rows := range map[string]string{
		"ydivb": `{Zm_o,2,argList{Ymb}},`,
		"ydivl": `{Zm_o,2,argList{Yml}},`,
		"yimul": `{Zm_o,2,argList{Yml}},{Zib_rr,1,argList{Yi8,Yrl}},{Zil_rr,1,argList{Yi32,Yrl}},{Zm_r,2,argList{Yml,Yrl}},`,
	} {
		match := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(match) != 2 || regexp.MustCompile(`\s+`).ReplaceAllString(string(match[1]), "") != rows {
			t.Fatal("complete actual Go multiply rows changed", table)
		}
	}
	actual := regexp.MustCompile(`\{A(?:I?MUL)[BWLQ], [^\n]+`).FindAllString(string(data), -1)
	want := []string{
		`{AIMULB, ydivb, Pb, opBytes{0xf6, 05}},`,
		`{AIMULL, yimul, Px, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AIMULQ, yimul, Pw, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AIMULW, yimul, Pe, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AMULB, ydivb, Pb, opBytes{0xf6, 04}},`,
		`{AMULL, ydivl, Px, opBytes{0xf7, 04}},`,
		`{AMULQ, ydivl, Pw, opBytes{0xf7, 04}},`,
		`{AMULW, ydivl, Pe, opBytes{0xf7, 04}},`,
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatal("complete opcode/table/prefix/byte-offset attributes changed", actual)
	}
}

func TestX86ImplicitMultiplyGrammarBanksAndMemoryBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ImplicitMultiplyCases(arch) {
			for _, register := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH BL BH CL CH DL DH BPB SIB DIB R8B R15B X0 Y0 Z0 K1 M0 FS TLS R16") {
				t.Run(arch+"/"+row.op+"/"+register, func(t *testing.T) {
					ins := Instr{Op: Op(row.op), Args: []Operand{{Kind: OpReg, Reg: Reg(register)}}, Raw: row.op + " " + register}
					before := ins
					before.Args = append([]Operand(nil), ins.Args...)
					gp := strings.Contains(" AX CX DX BX SP BP SI DI ", " "+register+" ") || arch == "amd64" && regexp.MustCompile(`^R(?:[89]|1[0-5])$`).MatchString(register)
					valid := gp
					if row.width == 1 {
						valid = gp && (arch != "386" || register != "SP") || strings.Contains(" AL AH BL BH CL CH DL DH ", " "+register+" ") || arch == "amd64" && strings.Contains(" BPB SIB DIB R8B R15B ", " "+register+" ")
					}
					_, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, arch)
					if !known || (err == nil) != valid || !reflect.DeepEqual(ins, before) {
						t.Fatal("complete named source bank/identity mismatch", valid, known, err)
					}
				})
			}
		}
		for _, instruction := range []string{"MULL $3", "MULL $1.0", "MULL $x(SB)", "MULL", "MULL AX,BX", "IMULB AX,BX", "MULL (AX)(SP*1)", "MULL (AX)(BX*3)", "MULL (AX)(BX)", "MULL $slot+0(FP)"} {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+instruction+"\nRET\n")
			if err != nil {
				continue // Malformed source syntax has already been rejected, not granted a typed effect.
			}
			ins := file.Funcs[0].Instrs[1]
			if _, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, arch); !known || err == nil {
				t.Fatal("invalid implicit form acquired numerical effect", arch, instruction)
			}
		}
		for _, instruction := range []string{"MULL x+1(FP)", "MULL -4(SP)", "MULL 4(AX)(SI*2)", "MULL table(SB)"} {
			ins := x86YMMReadSource(t, instruction)
			if _, known, err := x86ImplicitMultiplyProperties(ins.Op, ins, arch); !known || err != nil {
				t.Fatal("grammar inferred a storage permission/rejected valid memory shape", arch, instruction, err)
			}
			state := x86ResultState{}
			state.gp[0] = 255
			if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
				t.Fatal("shape alone initialized unowned FP/AUTO/SB/native storage", instruction)
			}
		}
	}
}

func TestX86ImplicitMultiplyIndependentStorageCannotBypassNUM(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move, push, pop, lea := goWordSize(target.arch), "MOVQ", "PUSHQ", "POPQ", "LEAQ"
		if target.arch == "386" {
			move, push, pop, lea = "MOVL", "PUSHL", "POPL", "LEAL"
		}
		for _, row := range []struct {
			name, params, storage string
			writes, knownValid    bool
		}{
			{"bool-input", "flag bool", "", true, true},
			{"bool-input-unwritten", "flag bool", "", false, false},
			{"unused-result-address", "", fmt.Sprintf("%s ret+0(FP),SI\n", lea), true, true},
			{"value-stack", "", push + " $7\n" + pop + " SI\n", true, true},
			{"input-store", "flag uint32", "MOVL $1,flag+0(FP)\n", true, false},
			{"unbacked-SP", "", move + " $7,-8(SP)\n", true, false},
		} {
			for _, initialized := range []bool{false, true} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/initialized=%t/%s", target.triple, row.name, initialized, api), func(t *testing.T) {
						result := 0
						if row.params != "" {
							result = word
						}
						body := row.storage
						if initialized {
							body += "MOVL $2,AX\nMOVL $3,BX\n"
						}
						body += "MULL BX\n"
						if row.writes {
							body += fmt.Sprintf("MOVL AX,ret+%d(FP)\n", result)
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", result+4, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value("+row.params+") uint32", target.arch, target.triple, api)
						if !initialized || !row.knownValid {
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatalf("storage syntax substituted for implicit NUM/result proof: output=%t error=%v", ir != "", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("independent checked storage lost a complete product", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ImplicitMultiplyAliasesReadBeforeWriteAndFlags(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, stem := range []string{"MUL", "IMUL"} {
			for _, source := range []string{"AL", "AH", "AX", "DX", "BP", "SI", "DI"} {
				if target.arch == "amd64" && source == "BP" {
					continue // Physical AMD64 frame role, independently rejected below.
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+stem+"/"+source+"/"+api, func(t *testing.T) {
						body := "MOVL $0x0302,AX\nMOVL $5,DX\n"
						want := uint64(10)
						if source == "AL" || source == "AX" {
							want = 4
						} else if source == "AH" {
							want = 6
						} else if source != "DX" {
							body += "MOVL $5," + source + "\n"
						}
						body += stem + "B " + source + "\nMOVW AX,ret+0(FP)\nRET\n"
						ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·Value(SB),4,$0-2\n"+body, "func Value() uint16", target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{want})
					})
				}
			}
			for _, row := range x86ImplicitMultiplyCases(target.arch) {
				if !strings.HasPrefix(row.op, stem) { // MUL and IMUL have independent sign rules.
					continue
				}
				for _, flag := range []string{"CS", "OS", "EQ", "MI", "PS", "overflow-CS", "overflow-OS"} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+row.op+"/status"+flag+"/"+api, func(t *testing.T) {
							move := map[int]string{1: "MOVB", 2: "MOVW", 4: "MOVL", 8: "MOVQ"}[row.width]
							input, multiplier, want := "-1", 1, uint64(0)
							condition := strings.TrimPrefix(flag, "overflow-")
							if condition != flag {
								multiplier, want = 2, 1
								if strings.HasPrefix(row.op, "IMUL") {
									input = fmt.Sprint((uint64(1) << uint(row.width*8-1)) - 1)
								}
							}
							source := fmt.Sprintf("TEXT ·Value(SB),4,$0-1\nCLD\nMOVL $0,AX\nCMPL AX,$0\n%s $%s,AX\n%s $%d,BX\n%s BX\nSET%s CX\nMOVB CX,ret+0(FP)\nRET\n", move, input, move, multiplier, row.op, condition)
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint8", target.arch, target.triple, api)
							if condition != "CS" && condition != "OS" {
								if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
									t.Fatal("multiply reused undefined status", err)
								}
								return
							}
							if err != nil {
								t.Fatal(err)
							}
							x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{want}) // Signed -1*1 has a nonzero high half but no overflow.
						})
					}
				}
			}
		}
	}
}
