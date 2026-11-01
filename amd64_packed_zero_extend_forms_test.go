package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Independent byte ratios, not values taken from the production spec.
var x86ZeroExtendTestRatios = []struct {
	suffix string
	input  int
	output int
}{
	{"BW", 1, 2}, {"BD", 1, 4}, {"BQ", 1, 8},
	{"WD", 2, 4}, {"WQ", 2, 8}, {"DQ", 4, 8},
}

func x86ZeroExtendAcceptedForms(opcode, arch string) []string {
	if !strings.HasPrefix(opcode, "V") {
		last := 15
		if arch == "386" {
			last = 7
		}
		return []string{fmt.Sprintf("%s X0,X%d", opcode, last), fmt.Sprintf("%s 8(AX),X%d", opcode, last)}
	}
	var rows []string
	for _, bank := range []string{"X", "Y", "Z"} {
		source, last := "X", 31
		if bank == "Z" && (strings.HasSuffix(opcode, "BW") || strings.HasSuffix(opcode, "WD") || strings.HasSuffix(opcode, "DQ")) {
			source = "Y"
		}
		if arch == "386" {
			last = 7
		}
		for _, input := range []string{source + "0", "8(AX)"} {
			rows = append(rows, fmt.Sprintf("%s %s,%s%d", opcode, input, bank, last))
			rows = append(rows, fmt.Sprintf("%s %s,K7,%s%d", opcode, input, bank, last),
				fmt.Sprintf("%s.Z %s,K1,%s%d", opcode, input, bank, last))
		}
	}
	// These select the two VEX optab rows rather than their EVEX aliases.
	rows = append(rows, opcode+" X0,X1", opcode+" X0,Y1")
	return rows
}

func TestX86PackedZeroExtendSpecsBindCompleteGoTables(t *testing.T) {
	dir := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(x86PackedZeroExtendSpecs) != 12 {
		t.Fatalf("unsigned family has %d names, want 12", len(x86PackedZeroExtendSpecs))
	}
	// Bind every operand class row, independently of the lowerer's accepted
	// form generator. Memory width attributes belong to each opcode below.
	legacyTable := "var yxm_q4 = []ytab{\n\t{Zm_r, 1, argList{Yxm, Yxr}},\n}"
	if !strings.Contains(string(legacy), legacyTable) {
		t.Fatal("Go changed the complete legacy register/memory operand table")
	}
	for _, table := range []string{"_yvbroadcastss", "_yvcvtdq2pd"} {
		want := "var " + table + " = []ytab{\n"
		want += "\t{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr}},\n"
		want += "\t{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yyr}},\n"
		for _, destination := range []string{"YxrEvex", "YyrEvex", "Yzr"} {
			source := "YxmEvex"
			if table == "_yvcvtdq2pd" && destination == "Yzr" {
				source = "YymEvex"
			}
			want += fmt.Sprintf("\t{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{%s, %s}},\n", source, destination)
			want += fmt.Sprintf("\t{zcase: Zevex_rm_k_r, zoffset: 3, args: argList{%s, Yknot0, %s}},\n", source, destination)
		}
		want += "}"
		if !strings.Contains(string(avx), want) {
			t.Fatalf("Go changed %s's complete VEX/EVEX operand table", table)
		}
	}
	for index, ratio := range x86ZeroExtendTestRatios {
		opcode := byte(0x30 + index)
		for _, prefix := range []string{"P", "VP"} {
			name := prefix + "MOVZX" + ratio.suffix
			spec, present := x86PackedZeroExtendSpecs[Op(name)]
			if !present || spec.inputBits != ratio.input*8 || spec.outputBits != ratio.output*8 || spec.vector != (prefix == "VP") || spec.opcode != opcode {
				t.Fatalf("independent unsigned ratio/encoding mismatch: %s %+v", name, spec)
			}
			if prefix == "P" {
				want := fmt.Sprintf("{A%s, yxm_q4, Pq4, opBytes{0x%02x}}", name, opcode)
				if !strings.Contains(string(legacy), want) {
					t.Fatalf("missing exact Go legacy row: %s", want)
				}
				continue
			}
			table := "_yvbroadcastss"
			if ratio.output == 2*ratio.input {
				table = "_yvcvtdq2pd"
			}
			marker := "{as: A" + name + ", ytab: " + table + ", prefix: Pavx, op: opBytes{"
			start := strings.Index(string(avx), marker)
			if start < 0 {
				t.Fatalf("missing exact Go AVX family row: %s", marker)
			}
			row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
			want := marker
			for _, width := range []int{128, 256} {
				want += fmt.Sprintf("\n\t\tavxEscape | vex%d | vex66 | vex0F38 | vexW0, 0x%02x,", width, opcode)
			}
			for _, width := range []int{128, 256, 512} {
				want += fmt.Sprintf("\n\t\tavxEscape | evex%d | evex66 | evex0F38 | evexW0, evexN%d | evexZeroingEnabled, 0x%02x,", width, width/8*ratio.input/ratio.output, opcode)
			}
			if row != want {
				t.Fatalf("changed complete Go prefix/opcode/width/exception attributes:\n%s\nwant:\n%s", row, want)
			}
		}
	}
	for _, source := range []string{string(legacy), string(avx)} {
		for _, match := range regexp.MustCompile(`\{(?:as: )?A(V?PMOVZX[A-Z]+),`).FindAllStringSubmatch(source, -1) {
			if _, exists := x86PackedZeroExtendSpecs[Op(match[1])]; !exists {
				t.Fatalf("Go added an unregistered unsigned family name %s", match[1])
			}
		}
	}
}

func TestX86PackedZeroExtendNamedMode32RetainsActualPhysicalContext(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, bank := range []string{"X", "Y"} {
			for _, high := range []int{8, 16, 31} {
				for _, args := range []string{fmt.Sprintf("X%d,%s0", high, bank), fmt.Sprintf("X0,%s%d", bank, high)} {
					row := "VPMOVZX" + ratio.suffix + " " + args
					listing, err := x86ExtensionGoListing(t, "386", row)
					if err != nil {
						t.Fatalf("actual mode32 Go source acceptance: %s: %v\n%s", row, err, listing)
					}
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					for _, target := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
						if _, err := Translate(file, Options{Goarch: "386", TargetTriple: target, Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("named high register acquired physical mode32 binding: %s: %v", row, err)
						}
					}
				}
			}
		}
	}
}

func TestX86PackedZeroExtendActualGoBytesBindRawWidths(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, row := range []string{"X0,X1", "X0,Y1", "8(AX),Y1", "X20,K3,X21", "X20,K3,Y21"} {
			instruction := "VPMOVZX" + ratio.suffix + " " + row
			listing, err := x86ExtensionGoListing(t, "amd64", instruction)
			if err != nil {
				t.Fatal(err, listing)
			}
			var code []byte
			for _, line := range strings.Split(listing, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 3 || fields[0] != "0x0000" || len(fields[1]) != 2 {
					continue
				}
				for _, field := range fields[1:] {
					if len(field) != 2 {
						break
					}
					value, err := strconv.ParseUint(field, 16, 8)
					if err != nil {
						break
					}
					code = append(code, byte(value))
				}
				break
			}
			decoded, length, recognized, err := decodedX86PackedExtendInstruction(code, 64)
			if !recognized || err != nil || length <= 0 || decoded.Op != Op("VPMOVZX"+ratio.suffix) {
				t.Fatalf("actual Go object did not decode as source family: %s/%x: %+v %v", instruction, code, decoded, err)
			}
			form, recognized, err := x86PackedZeroExtendProperties(decoded, "amd64")
			if !recognized || err != nil || form.memoryBytes != form.byteWidth*ratio.input/ratio.output {
				t.Fatalf("actual raw width lost its independent source ratio: %+v %v", form, err)
			}
		}
	}
}
