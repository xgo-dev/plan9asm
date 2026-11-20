package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

type x86BlendMinposCase struct {
	op, bank, operand string
	bits, width, dst  int
	ordinal           int
	legacy, minimum   bool
}

// Independent of the production maps: all three legacy/VEX blend pairs,
// X/Y VEX forms, both source roles and all four original output aliases;
// the two minimum-position forms additionally use both source aliases.
func x86BlendMinposCases() []x86BlendMinposCase {
	var rows []x86BlendMinposCase
	for _, family := range []struct {
		legacy, vector string
		bits           int
	}{{"BLENDVPS", "VBLENDVPS", 32}, {"BLENDVPD", "VBLENDVPD", 64}, {"PBLENDVB", "VPBLENDVB", 8}} {
		for _, width := range []int{0, 16, 32} {
			for _, memory := range []bool{false, true} {
				for dst := 0; dst < 4; dst++ {
					row := x86BlendMinposCase{op: family.legacy, bank: "X", operand: "X1", bits: family.bits, width: width, dst: dst, legacy: width == 0}
					if width != 0 {
						row.op = family.vector
					}
					if width == 32 {
						row.bank, row.operand = "Y", "Y1"
					}
					if memory {
						row.operand = "(BX)"
					}
					rows = append(rows, row)
				}
			}
		}
	}
	for _, op := range []string{"PHMINPOSUW", "VPHMINPOSUW"} {
		for _, operand := range []string{"(BX)", "X1", "X0"} {
			rows = append(rows, x86BlendMinposCase{op: op, bank: "X", operand: operand, bits: 16, width: 16, legacy: op == "PHMINPOSUW", minimum: true})
		}
	}
	for index := range rows {
		rows[index].ordinal = index
	}
	return rows
}

func (row x86BlendMinposCase) instruction() string {
	if row.minimum {
		return row.op + " " + row.operand + ",X0"
	}
	if row.legacy {
		return fmt.Sprintf("%s X0,%s,X%d", row.op, row.operand, row.dst)
	}
	return fmt.Sprintf("%s %s0,%s,%s2,%s%d", row.op, row.bank, row.operand, row.bank, row.bank, row.dst)
}

func x86BlendMinposOriginalCodes(t *testing.T, rows []x86BlendMinposCase) [][]byte {
	t.Helper()
	var body strings.Builder
	for _, row := range rows {
		body.WriteString(row.instruction() + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", body.String()+"RET")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("actual Go did not produce every original blend/minimum opcode boundary")
	}
	result := make([][]byte, len(rows))
	for index := range rows {
		result[index] = append([]byte(nil), code[pcs[index]:pcs[index+1]]...)
	}
	return result
}

func TestX86BlendMinposCompleteIndependentGoRowsAndAttributes(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"var yblendvpd = []ytab{\n\t{Z_m_r, 1, argList{Yxr0, Yxm, Yxr}},\n}",
		"var yxm_q4 = []ytab{\n\t{Zm_r, 1, argList{Yxm, Yxr}},\n}",
	} {
		if !strings.Contains(string(legacy), table) {
			t.Fatal("independent complete legacy operand/zcase/offset table changed", table)
		}
	}
	for _, row := range []string{
		"{ABLENDVPS, yblendvpd, Pq4, opBytes{0x14}},",
		"{ABLENDVPD, yblendvpd, Pq4, opBytes{0x15}},",
		"{APBLENDVB, yblendvpd, Pq4, opBytes{0x10}},",
		"{APHMINPOSUW, yxm_q4, Pq4, opBytes{0x41}},",
	} {
		if strings.Count(string(legacy), row) != 1 {
			t.Fatal("independent full legacy opcode attributes changed", row)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, table, zcase, opcode string }{
		{"VBLENDVPS", "_yvblendvpd", "Zvex_hr_rm_v_r", "0x4A"},
		{"VBLENDVPD", "_yvblendvpd", "Zvex_hr_rm_v_r", "0x4B"},
		{"VPBLENDVB", "_yvblendvpd", "Zvex_hr_rm_v_r", "0x4C"},
		{"VPHMINPOSUW", "_yvaesimc", "Zvex_rm_v_r", "0x41"},
	} {
		count, widths, mapName := 0, []string{"128", "256"}, "vex0F3A"
		if row.name == "VPHMINPOSUW" {
			widths, mapName = widths[:1], "vex0F38"
		}
		var opbytes []string
		for _, width := range widths {
			opbytes = append(opbytes, "avxEscape | vex"+width+" | vex66 | "+mapName+" | vexW0", row.opcode)
		}
		for _, rule := range rules {
			if rule.Opcode != row.name {
				continue
			}
			bank, args := "x", ""
			if count == 1 {
				bank = "y"
			}
			args = "Y" + bank + "r,Y" + bank + "m,Y" + bank + "r,Y" + bank + "r"
			if row.name == "VPHMINPOSUW" {
				args = "Yxm,Yxr"
			}
			if count >= len(widths) || rule.RowIndex != count || rule.EncodingOffset != count*2 || rule.ZOffset != 2 ||
				rule.Ytab != row.table || rule.ZCase != row.zcase || rule.Prefix != "Pavx" ||
				strings.Join(rule.Classes, ",") != args || strings.Join(rule.OpBytes, ";") != strings.Join(opbytes, ";") {
				t.Fatal("independent complete VEX row/prefix/offset/attributes changed", row.name, rule)
			}
			count++
		}
		if count != len(widths) {
			t.Fatal("complete VEX family row missing", row.name, count)
		}
	}
}

func x86BlendMinposProgram(rows []x86BlendMinposCase, codes [][]byte, arch string, raw bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("blend%d", row.ordinal)
		if row.minimum {
			name = fmt.Sprintf("minpos%d", row.ordinal-72)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s old+0(FP),AX\n%s input+%d(FP),BX\n%s out+%d(FP),DI\n", name, 3*word, move, move, word, move, 2*word)
			source.WriteString("VMOVUPS (AX),Z0\nVMOVUPS (AX),Z1\n")
			if row.operand != "(BX)" {
				fmt.Fprintf(&source, "MOVOU (BX),%s\n", row.operand)
			}
			fmt.Fprintf(&declarations, "func %s(old *[64]byte,input *[16]byte,out *[112]byte)\n", name)
		} else {
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-%d\n%s base+0(FP),AX\n%s source+%d(FP),BX\n%s mask+%d(FP),CX\n%s out+%d(FP),DI\n", name, 4*word, move, move, word, move, 2*word, move, 3*word)
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", register)
			}
			transport := "MOVOU"
			if row.width == 32 {
				transport = "VMOVUPS"
			}
			fmt.Fprintf(&source, "%s (CX),%s0\n%s (BX),%s1\n", transport, row.bank, transport, row.bank)
			fmt.Fprintf(&declarations, "func %s(base *[64]byte,source,mask *[32]byte,out *[112]byte)\n", name)
		}
		if raw {
			for _, value := range codes[index] {
				fmt.Fprintf(&source, "BYTE $%#x\n", value)
			}
		} else {
			source.WriteString(row.instruction() + "\n")
		}
		fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nVMOVUPS Y%d,64(DI)\nVMOVUPS X%d,96(DI)\nRET\n", row.dst, row.dst, row.dst)
	}
	return source.String(), declarations.String()
}

func TestX86BlendMinposOriginalDirectoryAndGoBytes(t *testing.T) {
	rows := x86BlendMinposCases()
	if len(rows) != 78 {
		t.Fatal("original blend72/minimum6 directory changed", len(rows))
	}
	codes := x86BlendMinposOriginalCodes(t, rows)
	counts := make(map[string]int)
	for index, row := range rows {
		counts[row.op]++
		code := codes[index]
		if row.legacy {
			opcode := map[string]byte{"BLENDVPS": 0x14, "BLENDVPD": 0x15, "PBLENDVB": 0x10, "PHMINPOSUW": 0x41}[row.op]
			if len(code) < 5 || string(code[:4]) != string([]byte{0x66, 0x0f, 0x38, opcode}) {
				t.Fatal("independent actual legacy opcode/prefix changed", row.instruction(), code)
			}
		} else if len(code) < 4 || code[0] != 0xc4 && code[0] != 0xc5 {
			t.Fatal("actual VEX instruction lost its generation", row.instruction(), code)
		}
	}
	for _, op := range []string{"BLENDVPS", "BLENDVPD", "PBLENDVB"} {
		if counts[op] != 8 || counts["V"+op] != 16 {
			t.Fatal("blend width/source/destination union changed", counts)
		}
	}
	if counts["PHMINPOSUW"] != 3 || counts["VPHMINPOSUW"] != 3 {
		t.Fatal("minimum-position source aliases changed", counts)
	}
	for _, target := range x86RawReturnTargets {
		// Actual Go accepts the complete original AMD64 sources and the
		// separately adapted low-bank mode32 raw program. Four-operand
		// named VEX source has its independent Go rejection below.
		for _, raw := range []bool{false, true} {
			selected, selectedCodes := rows, codes
			if target.arch == "386" && !raw {
				selected, selectedCodes = nil, nil
				for index, row := range rows {
					if row.minimum || row.legacy {
						selected, selectedCodes = append(selected, row), append(selectedCodes, codes[index])
					}
				}
			}
			source, _ := x86BlendMinposProgram(selected, selectedCodes, target.arch, raw)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
		}
	}
	for _, row := range rows {
		if !row.legacy && !row.minimum && row.dst == 3 {
			requireX86GoAssemblerResult(t, "386", "TEXT f(SB),4,$0-0\n"+row.instruction()+"\nRET\n", false)
		}
	}
}

func x86BlendMinposOriginalSourceObjects(t *testing.T, first, end int) {
	t.Helper()
	rows := x86BlendMinposCases()
	codes := x86BlendMinposOriginalCodes(t, rows)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for initialized original blend/minimum objects")
	}
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			var selected []x86BlendMinposCase
			var selectedCodes [][]byte
			for index := first; index < end; index++ {
				row := rows[index]
				if target.arch == "386" && !raw && !row.legacy && !row.minimum {
					continue
				}
				selected, selectedCodes = append(selected, row), append(selectedCodes, codes[index])
			}
			if len(selected) == 0 {
				continue // No named four-operand Go.386 row belongs to this batch.
			}
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				source, declarations := x86BlendMinposProgram(selected, selectedCodes, target.arch, raw)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
						if err != nil {
							t.Fatal("original initialized programs must translate, not be relabeled format-only", err)
						}
						compileLLVMToObject(t, llc, target.triple, "blend-minpos-original.ll", "blend-minpos-original.o", ir)
					})
				}
			})
		}
	}
}

func TestX86BlendMinposOriginalInitializedObjectsBatch00(t *testing.T) {
	x86BlendMinposOriginalSourceObjects(t, 0, 48)
}

func TestX86BlendMinposOriginalInitializedObjectsBatch01(t *testing.T) {
	x86BlendMinposOriginalSourceObjects(t, 48, 78)
}

func TestX86BlendMinposMissingInputsRemainContext(t *testing.T) {
	rows := x86BlendMinposCases()
	codes := x86BlendMinposOriginalCodes(t, rows)
	for index, row := range rows {
		if row.dst != 3 && !row.minimum {
			continue
		}
		for _, arch := range []string{"386", "amd64"} {
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			for _, missing := range []string{"source-pointer", "base-pointer", "mask-pointer"} {
				if row.minimum && missing == "mask-pointer" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%s/%s", arch, row.op, row.operand, missing), func(t *testing.T) {
					source, declaration := x86BlendMinposProgram([]x86BlendMinposCase{row}, [][]byte{codes[index]}, arch, true)
					move := "MOVQ"
					if arch == "386" {
						move = "MOVL"
					}
					field, register, offset := "source", "BX", goWordSize(arch)
					if row.minimum {
						field = "input"
					}
					if missing == "base-pointer" {
						field, register, offset = "base", "AX", 0
						if row.minimum {
							field = "old"
						}
					} else if missing == "mask-pointer" {
						field, register, offset = "mask", "CX", 2*goWordSize(arch)
					}
					producer := fmt.Sprintf("%s %s+%d(FP),%s\n", move, field, offset, register)
					changed := strings.Replace(source, producer, "", 1)
					if changed == source {
						t.Fatal("missing-input mutation did not change its actual producer")
					}
					x86LEAActualTargetGoObject(t, arch, triple, changed)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw family origin supplied a missing initialized pointer/input", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86BlendMinposOriginalRuntimeSourceAndCRemainExact(t *testing.T) {
	for _, row := range []struct{ file, function, builderHash, oracleHash string }{
		{"amd64_blend_variable_runtime_test.go", "TestX86VariableBlendMemoryAndViewsRuntime", "5ac3cb2ea8200c04a73be0f43c14a23357abe7e025d7b74fb8830280a2e25324", "a2070b7ebb6419a01be94fb8c0efce84408cfbc6fd2a6f1079e9fbbe6951e28a"},
		{"amd64_minpos_runtime_test.go", "TestX86MinimumPositionMemoryAndViewsRuntime", "663b299f6c4f9479b33130d6e7ca3a393f199568de3efcae874185f6b2bb1fe0", "5a989e4f9487f00f687d307e4a44607e1f111a709bfdc85d1c9aa1d965398936"},
	} {
		data, err := os.ReadFile(row.file)
		if err != nil {
			t.Fatal(err)
		}
		positions := token.NewFileSet()
		syntax, err := parser.ParseFile(positions, row.file, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		ast.Inspect(syntax, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			start, end := -1, -1
			for index, statement := range block.List {
				text := string(data[positions.Position(statement.Pos()).Offset:positions.Position(statement.End()).Offset])
				if text == "var source, declarations, checks strings.Builder" {
					start = positions.Position(statement.Pos()).Offset
				}
				if start >= 0 && strings.HasPrefix(text, "file, err := Parse(") && index > 0 {
					end = positions.Position(block.List[index-1].End()).Offset
					break
				}
			}
			if start >= 0 && end > start {
				if found || fmt.Sprintf("%x", sha256.Sum256(data[start:end])) != row.builderHash {
					t.Fatal("complete original ASM/signature/C-observation builder changed", row.function)
				}
				found = true
			}
			return true
		})
		if !found {
			t.Fatal("original complete program builder disappeared", row.function)
		}
		oracle := x86VariableBlendOracleC
		if strings.Contains(row.file, "minpos") {
			oracle = x86MinimumPositionOracleC
		}
		if fmt.Sprintf("%x", sha256.Sum256([]byte(oracle))) != row.oracleHash {
			t.Fatal("original complete independent C values/canaries/guard observations changed", row.function)
		}
	}
}
