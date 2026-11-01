package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type ordinaryGlobalArithmeticCase struct {
	op, stem        string
	bits            int
	carry, highByte bool
	three           bool
	immediate       int64
}

// Independent closed inventory. Unary/implicit multiply/divide, bit strings,
// ADX and memory destinations are not this read-only mem-to-GP role.
func ordinaryGlobalArithmeticCases(arch string) []ordinaryGlobalArithmeticCase {
	var rows []ordinaryGlobalArithmeticCase
	for width, suffix := range []string{"B", "W", "L", "Q"} {
		if arch == "386" && suffix == "Q" {
			continue
		}
		bits := []int{8, 16, 32, 64}[width]
		for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
			row := ordinaryGlobalArithmeticCase{op: stem + suffix, stem: stem, bits: bits}
			rows = append(rows, row)
			if stem == "ADC" || stem == "SBB" {
				row.carry = true
				rows = append(rows, row)
				row.carry = false
			}
			if bits == 8 {
				row.highByte = true
				rows = append(rows, row)
			}
		}
		if bits == 8 {
			continue
		}
		rows = append(rows, ordinaryGlobalArithmeticCase{op: "IMUL" + suffix, stem: "IMUL", bits: bits})
		// Both Yi8/Yi32 rows, positive/negative signed values, W truncation,
		// and Q's real sign extension of the encoded imm32 are independent.
		for _, immediate := range []int64{-128, 128, 0x80000000, 0xffffffff} {
			rows = append(rows, ordinaryGlobalArithmeticCase{
				op: "IMUL3" + suffix, stem: "IMUL", bits: bits, three: true, immediate: immediate,
			})
		}
	}
	return rows
}

func ordinaryGlobalArithmeticInstruction(row ordinaryGlobalArithmeticCase) string {
	register := "AX"
	if row.highByte {
		register = "AH"
	}
	if row.three {
		return fmt.Sprintf("%s $%d,·words+1(SB),%s", row.op, row.immediate, register)
	}
	return row.op + " ·words+1(SB)," + register
}

func ordinaryGlobalArithmeticSource(arch string) (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("var words [5]uint64\n")
	word, move, seed := 8, "MOVQ", "0x1234567889abcdef"
	if arch == "386" {
		word, move, seed = 4, "MOVL", "0x89abcdef"
	}
	for index, row := range ordinaryGlobalArithmeticCases(arch) {
		fmt.Fprintf(&declarations, "func arithmetic%d(out *[16]byte)\n", index)
		fmt.Fprintf(&source, "TEXT ·arithmetic%d(SB),4,$0-%d\n%s out+0(FP),DI\n%s $%s,AX\n",
			index, word, move, move, seed)
		if row.stem == "ADC" || row.stem == "SBB" {
			if row.carry {
				source.WriteString("STC\n")
			} else {
				source.WriteString("CLC\n")
			}
		}
		source.WriteString(ordinaryGlobalArithmeticInstruction(row) + "\n")
		if arch == "386" {
			source.WriteString("MOVL AX,0(DI)\nMOVL $0,4(DI)\n")
		} else {
			source.WriteString("MOVQ AX,0(DI)\n")
		}
		source.WriteString("SETCS 8(DI)\nSETOS 9(DI)\n")
		if row.stem != "IMUL" {
			source.WriteString("SETEQ 10(DI)\nSETMI 11(DI)\nSETPS 12(DI)\n")
			if row.stem != "AND" && row.stem != "OR" && row.stem != "XOR" {
				source.WriteString("LAHF\nMOVB AH,13(DI)\n")
			}
		}
		source.WriteString("RET\n")
	}
	return source.String(), declarations.String()
}

func TestGoModuleOrdinaryGlobalArithmeticOfficialRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, arch := range []string{"amd64", "386"} {
		names := make(map[string]bool)
		for _, row := range ordinaryGlobalArithmeticCases(arch) {
			names[row.op] = true
		}
		want := 34
		if arch == "386" {
			want = 25
		}
		if len(names) != want {
			t.Fatal("independent opcode inventory changed", arch, len(names), want)
		}
		for name := range names {
			table := "yaddl"
			if strings.HasPrefix(name, "IMUL3") {
				table = "yimul3"
			} else if strings.HasPrefix(name, "IMUL") {
				table = "yimul"
			} else if strings.HasSuffix(name, "B") {
				table = "yxorb"
			}
			pattern := `(?m)^\s*\{A` + name + `,\s*` + table + `,`
			if len(regexp.MustCompile(pattern).FindAllString(source, -1)) != 1 {
				t.Fatal("actual official opcode/table role changed", name, table)
			}
		}
		assembly, _ := ordinaryGlobalArithmeticSource(arch)
		goAssemblerOracleOutput(t, arch, assembly, "", true)
	}
	for table, row := range map[string]string{
		"yxorb":  "{Zm_r,1,argList{Ymb,Yrb}}",
		"yaddl":  "{Zm_r,1,argList{Yml,Yrl}}",
		"yimul":  "{Zm_r,2,argList{Yml,Yrl}}",
		"yimul3": "{Zibm_r,2,argList{Yi8,Yml,Yrl}}",
	} {
		block := regexp.MustCompile(`(?ms)^var ` + table + ` = \[\]ytab\{(.*?)^\}`).FindStringSubmatch(source)
		if len(block) != 2 || !strings.Contains(strings.Join(strings.Fields(block[1]), ""), row+",") {
			t.Fatal("complete official read-only source row disappeared", table, row)
		}
		if table == "yimul3" && !strings.Contains(strings.Join(strings.Fields(block[1]), ""), "{Zibm_r,2,argList{Yi32,Yml,Yrl}},") {
			t.Fatal("IMUL3 Yi32 source row disappeared")
		}
	}
}

func TestGoModuleOrdinaryGlobalArithmeticCompleteFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			assembly, declarations := ordinaryGlobalArithmeticSource(target.arch)
			for _, api := range []string{"public", "owned-context"} {
				t.Run(api, func(t *testing.T) {
					pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
					ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(assembly), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("typed read-only ALU/IMUL source needs no SDK capture", err)
					}
					count := len(ordinaryGlobalArithmeticCases(target.arch))
					if got := strings.Count(ir, "load volatile i"); got != count {
						t.Fatalf("not every exact mutable source load remains observable: got %d, want %d", got, count)
					}
					compileLLVMToObject(t, llc, target.triple, "ordinary-arithmetic.ll", "ordinary-arithmetic.o", ir)
				})
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalArithmeticRejectsOtherAuthority(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"unknown-destination", "var words [5]uint64", "ADDQ ·words(SB),DX"},
		{"unknown-CF", "var words [5]uint64", "ADCQ ·words(SB),AX"},
		{"header", "var words []uint64", "ADDQ ·words(SB),AX"},
		{"pointer", "var words *uint64", "IMULQ ·words(SB),AX"},
		{"past-extent", "var words [5]uint64", "ADDQ ·words+33(SB),AX"},
		{"padding", "var words struct { B byte; Q uint64 }", "ADDL ·words+1(SB),AX"},
		{"memory-destination", "var words [5]uint64", "ADDQ AX,·words(SB)"},
		{"unary-memory-RMW", "var words [5]uint64", "INCQ ·words(SB)"},
		{"memory-memory", "var words [5]uint64", "ADDQ ·words(SB),·words+8(SB)"},
		{"logic-AF", "var words [5]uint64", "ANDQ ·words(SB),AX\nLAHF"},
		{"IMUL-ZF", "var words [5]uint64", "IMULQ ·words(SB),AX\nSETEQ CL"},
		{"IMUL-PF", "var words [5]uint64", "IMULQ ·words(SB),AX\nSETPS CL"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\n"+row.declaration+"\nfunc view() uint32\n")
				ir, err := ordinaryGlobalReadRequest(t, pkg, ordinaryGlobalLoadBoundarySource(row.body), "amd64", "x86_64-unknown-linux-gnu", api)
				if row.name == "memory-memory" {
					// Encoder grammar rejection is distinct from missing NUM/context.
					if ir != "" || err == nil || !strings.Contains(err.Error(), "operands do not match Go 1.27's register/memory rows") {
						t.Fatal("invalid ALU memory-memory form was not rejected", err)
					}
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("arithmetic read supplied unrelated authority", err)
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalArithmeticDeadReadStaysVolatile(t *testing.T) {
	for _, row := range []string{"ADDQ ·words(SB),AX", "ANDQ ·words(SB),AX", "IMUL3Q $0,·words(SB),AX"} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, ordinaryGlobalReadPackage,
					"package ordinaryglobals\nvar words [5]uint64\nfunc view() uint32\n")
				assembly := []byte("TEXT ·view(SB),4,$0-4\nMOVQ $7,AX\n" + row + "\nMOVL $0,ret+0(FP)\nRET\n")
				goAssemblerOracleOutput(t, "amd64", string(assembly), "", true)
				ir, err := ordinaryGlobalReadRequest(t, pkg, assembly, "amd64", "x86_64-unknown-linux-gnu", api)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(ir, "load volatile i64") != 1 ||
					strings.Count(x86MulDivRoundOptimize(t, ir), "load volatile i64") != 1 {
					t.Fatal("discarded arithmetic/zero product suppressed the actual global read")
				}
			})
		}
	}
}

func TestGoModuleOrdinaryGlobalArithmeticReadShapeGuards(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range ordinaryGlobalArithmeticCases(arch) {
			for _, mutation := range []string{"raw", "origin", "return", "address", "unbound", "segment", "write"} {
				t.Run(arch+"/"+ordinaryGlobalArithmeticInstruction(row)+"/"+mutation, func(t *testing.T) {
					ins := x86PureGPUnknownInstruction(t, ordinaryGlobalArithmeticInstruction(row))
					switch mutation {
					case "raw":
						ins.x86Encoded = true
					case "origin":
						ins.x86SourceRaw = &x86SourceRawInstruction{}
					case "return":
						ins.x86RawNearReturn = &x86RawNearReturnForm{}
					case "address":
						ins.x86AddressBits = 16
					case "unbound":
						ins.x86UnboundAddressOverride = true
					case "segment":
						ins.x86SegmentPrefix = 0x64
					case "write":
						ins.Args[len(ins.Args)-1] = Operand{Kind: OpSym, Sym: "·words(SB)"}
					}
					if _, _, known := goReadOnlyOperand(ins, arch); known {
						t.Fatal("raw/override/write instruction acquired a named read role", mutation)
					}
				})
			}
		}
	}
}
