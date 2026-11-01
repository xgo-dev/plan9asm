package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Keep the discovering programs, complete truth tables, C references and
// observations independent of this smaller native-input counterexample.
func x86TernaryOriginalRuntimeProgramsUnchanged(t *testing.T) {
	t.Helper()
	for _, original := range []struct{ path, name, hash string }{
		{"amd64_ternary_logic_runtime_test.go", "TestCrossLinuxRuntimeMatrixX86TernaryAllTruthTablesAndForms", "051de207c52d2a346802faa78b0d505913ded1aae784f585690df6adf19efb9e"},
		{"amd64_ternary_logic_fault_runtime_unix_test.go", "TestCrossLinuxRuntimeMatrixX86TernaryDeadReadsAndMaskedFaults", "48a52e289c20ccd8fcd5999beb51cdad33e72bfa05cd5a4a6bc7d76b9c2e5d3d"},
	} {
		data, err := os.ReadFile(original.path)
		if err != nil {
			t.Fatal(err)
		}
		set := token.NewFileSet()
		syntax, err := parser.ParseFile(set, original.path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, declaration := range syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != original.name {
				continue
			}
			start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
			body := string(data[start:end])
			if original.name == "TestCrossLinuxRuntimeMatrixX86TernaryDeadReadsAndMaskedFaults" {
				// Only the host selector changes: preserve the old complete
				// function hash, including every ASM/C byte, case and observation.
				const portable = "llc, clang, triple, prefix := x86TernaryGuardPageRuntimeTools(t)"
				const previous = "llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)"
				if strings.Count(body, portable) != 1 {
					t.Fatal("original integer guard-page oracle lost actual-host execution")
				}
				body = strings.Replace(body, portable, previous, 1)
			}
			if fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != original.hash {
				t.Fatal("original ternary runtime source/reference/observations changed", original.name)
			}
			found = true
		}
		if !found {
			t.Fatal("original ternary runtime disappeared", original.name)
		}
	}
}

func TestX86TernaryInitializedNativeReadRetainsConstantAccess(t *testing.T) {
	x86TernaryOriginalRuntimeProgramsUnchanged(t)
	for _, opcode := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
			fixture := func(first string) string {
				return "TEXT ·view(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ p+8(FP),SI\n" +
					opcode + " $0," + first + "," + bank + "1," + bank + "2\nVMOVDQU64 Z2,(AX)\nRET\n"
			}
			register, memory := fixture(bank+"0"), fixture("(SI)")
			goAssemblerOracleOutput(t, "amd64", register+strings.Replace(memory, "·view", "·memory", 1), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(opcode+"/"+bank+"/"+api, func(t *testing.T) {
					// Selector zero needs no vector data, but its physical memory
					// form must still access the incoming pointer. The positive
					// register control must succeed before diagnosing that gap.
					if _, err := x86ScalarFPBitViewAPI(t, register, "func view(out,p *byte)", "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Fatal("register positive control failed before native-read comparison", err)
					}
					ir, err := x86ScalarFPBitViewAPI(t, memory, "func view(out,p *byte)", "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil {
						t.Fatal("changing only r/m to a genuine incoming pointer lost paired E4 continuation", err)
					}
					if !strings.Contains(ir, fmt.Sprintf("load volatile <%d x i8>", width)) {
						t.Fatal("constant truth table or dead numerical input removed the original memory access")
					}
				})
			}
		}
	}
}

type x86TernaryOracleRow struct {
	row                        string
	width, sourceWidth, mask   int
	destination, laneBits      int
	broadcast, zeroing, memory bool
}

// Two Go opcodes, three physical widths, register/full-tuple/broadcast
// sources and unmasked/merging/zeroing modes. All 256 Boolean selectors and
// five register-alias partitions already have their independent cheap oracle
// in TestX86TernaryResultCompleteBooleanDomain; do not multiply that axis by
// this physical matrix or by target object compilation.
func x86TernaryCompleteOracleRows() []x86TernaryOracleRow {
	var rows []x86TernaryOracleRow
	for _, opcode := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		bits := 32
		if opcode == "VPTERNLOGQ" {
			bits = 64
		}
		for _, bank := range []struct {
			name  string
			width int
		}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
			for _, source := range []string{"register", "memory", "broadcast"} {
				for _, mode := range []string{"", "merge", "zero"} {
					row := x86TernaryOracleRow{
						width: bank.width, sourceWidth: bank.width, laneBits: bits,
						mask: -1, destination: 3, memory: source != "register",
						broadcast: source == "broadcast", zeroing: mode == "zero",
					}
					first, suffix, mask := bank.name+"0", "", ""
					if row.memory {
						first = "-64(AX)(CX*4)"
					}
					if row.broadcast {
						suffix, row.sourceWidth = ".BCST", bits/8
					}
					if mode != "" {
						mask, row.mask, row.destination = ",K7", 3, 4
					}
					if row.zeroing {
						suffix += ".Z"
					}
					row.row = fmt.Sprintf("%s%s $150,%s,%s1%s,%s2", opcode, suffix, first, bank.name, mask, bank.name)
					rows = append(rows, row)
				}
			}
		}
	}
	return rows
}

func x86TernaryCompleteOfficialGoAttributes(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86", "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	begin := strings.Index(text, "var _yvalignd = []ytab{")
	if begin < 0 {
		t.Fatal("official Go omitted the ternary operand table")
	}
	table := strings.SplitN(text[begin:], "\n}", 2)[0]
	if strings.Count(table, "{zcase:") != 6 {
		t.Fatal("official ternary operand-table denominator changed", table)
	}
	for _, classes := range [][2]string{{"YxmEvex", "YxrEvex"}, {"YymEvex", "YyrEvex"}, {"Yzm", "Yzr"}} {
		for _, row := range []string{
			"{zcase: Zevex_i_rm_v_r, zoffset: 0, args: argList{Yu8, " + classes[0] + ", " + classes[1] + ", " + classes[1] + "}}",
			"{zcase: Zevex_i_rm_v_k_r, zoffset: 3, args: argList{Yu8, " + classes[0] + ", " + classes[1] + ", Yknot0, " + classes[1] + "}}",
		} {
			if !strings.Contains(table, row) {
				t.Fatal("complete Go ternary zcase/offset/operand classes changed", row)
			}
		}
	}
	for _, opcode := range []struct{ name, w, broadcast string }{
		{"VPTERNLOGD", "evexW0", "evexBcstN4"},
		{"VPTERNLOGQ", "evexW1", "evexBcstN8"},
	} {
		begin := strings.Index(text, "{as: A"+opcode.name+",")
		if begin < 0 {
			t.Fatal("official Go omitted ternary member", opcode.name)
		}
		block := strings.SplitN(text[begin:], "\n\t}},", 2)[0]
		if !strings.Contains(block, "ytab: _yvalignd, prefix: Pavx, op: opBytes{") || strings.Count(block, "avxEscape") != 3 {
			t.Fatal("official ternary opcode/header/width denominator changed", block)
		}
		for _, width := range []struct{ encoding, tuple string }{{"evex128", "evexN16"}, {"evex256", "evexN32"}, {"evex512", "evexN64"}} {
			attributes := "avxEscape | " + width.encoding + " | evex66 | evex0F3A | " + opcode.w + ", " +
				width.tuple + " | " + opcode.broadcast + " | evexZeroingEnabled, 0x25,"
			if !strings.Contains(block, attributes) {
				t.Fatal("complete ternary opcode/map/W/tuple/broadcast/zeroing attributes changed", attributes)
			}
		}
	}
}

func TestX86TernaryCompleteTypedClassRegistration(t *testing.T) {
	x86TernaryCompleteOfficialGoAttributes(t)
	rows := x86TernaryCompleteOracleRows()
	if len(rows) != 54 {
		t.Fatal("complete two-name/nine-mode/three-width ternary inventory changed", len(rows))
	}
	var source strings.Builder
	for index, row := range rows {
		fmt.Fprintf(&source, "TEXT ternaryFormat%d(SB),4,$0-0\n%s\nRET\n", index, row.row)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	for _, row := range rows {
		t.Run(row.row, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil || !effect.requiresResultProof {
				t.Fatal("complete ternary class lacks mandatory typed numerical effects", known, err)
			}
			reads, writes := make(map[int]bool), make(map[int]bool)
			for _, operand := range effect.operands {
				want := int64(row.width)
				if operand.index == 1 {
					want = int64(row.sourceWidth)
				} else if operand.index == row.mask {
					want = 8
				}
				if operand.index == 0 || operand.width != want {
					t.Fatal("selector is not vector data; full tuple, BCST and K widths must remain distinct", operand)
				}
				reads[operand.index] = reads[operand.index] || operand.read
				writes[operand.index] = writes[operand.index] || operand.write
			}
			// Selector 150 is A XOR B XOR C, so even zero masking
			// consumes the old destination as data, not merely for merge.
			if !reads[1] || !reads[2] || !reads[row.destination] || !writes[row.destination] ||
				row.mask >= 0 && !reads[row.mask] || writes[1] || writes[2] ||
				effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
				t.Fatal("ternary source/old-destination/mask roles or unchanged FLAGS lost", effect)
			}
		})
	}
}
