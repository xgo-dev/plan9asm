package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

type x86PackedReductionOracleRow struct {
	row, mnemonic                     string
	width, first, second, destination int
	dot, legacy                       bool
}

// Independent complete yxshuf/_yvdppd/_yvblendpd and yxm/_yvaddsubpd
// families: five dot shapes and twelve horizontal shapes, register/memory.
// Selectors and every byte dependency are separate inexpensive unit axes.
func x86PackedReductionOracleRows() []x86PackedReductionOracleRow {
	var rows []x86PackedReductionOracleRow
	for _, op := range []string{"DPPD", "DPPS", "VDPPD", "VDPPS"} {
		banks := []string{"X"}
		if op == "VDPPS" {
			banks = append(banks, "Y")
		}
		for _, bank := range banks {
			for _, memory := range []bool{false, true} {
				first := bank + "0"
				if memory {
					first = "(BX)"
				}
				row := x86PackedReductionOracleRow{
					row: op + " $255," + first + "," + bank + "1", mnemonic: strings.ToLower(op),
					width: 16, first: 1, second: 2, destination: 2, dot: true, legacy: !strings.HasPrefix(op, "V"),
				}
				if bank == "Y" {
					row.width = 32
				}
				if !row.legacy {
					row.row += "," + bank + "2"
					row.destination = 3
				}
				rows = append(rows, row)
			}
		}
	}
	for _, op := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD", "VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD"} {
		banks := []string{"X"}
		if strings.HasPrefix(op, "V") {
			banks = append(banks, "Y")
		}
		for _, bank := range banks {
			for _, memory := range []bool{false, true} {
				first := bank + "0"
				if memory {
					first = "(BX)"
				}
				row := x86PackedReductionOracleRow{
					row: op + " " + first + "," + bank + "1", mnemonic: strings.ToLower(op),
					width: 16, first: 0, second: 1, destination: 1, legacy: !strings.HasPrefix(op, "V"),
				}
				if bank == "Y" {
					row.width = 32
				}
				if !row.legacy {
					row.row += "," + bank + "2"
					row.destination = 2
				}
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func x86PackedReductionOriginalRuntimeProgramsUnchanged(t *testing.T) {
	t.Helper()
	for _, original := range []struct{ path, name, hash string }{
		{"amd64_lower_dot_float_test.go", "TestAMD64PackedFloatingDotRuntimeSemantics", "b928e394bd039f7f23a0fcbded8d22a0fbdb343d9d61b98c11d48bc95dcd11e5"},
		{"amd64_horizontal_float_numerical_test.go", "TestCrossLinuxRuntimeMatrixX86HorizontalFloatCompletePhysicalSemantics", "8195e2105b0760edd32d4661d4af4909e3cbbd52819b3bdf9a62554f2b1ed076"},
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
			if fmt.Sprintf("%x", sha256.Sum256(data[start:end])) != original.hash {
				t.Fatal("original initialized runtime source/reference/observations changed", original.name)
			}
			found = true
		}
		if !found {
			t.Fatal("original runtime disappeared", original.name)
		}
	}
}

func TestX86PackedReductionOriginalInitializedNativePrograms(t *testing.T) {
	x86PackedReductionOriginalRuntimeProgramsUnchanged(t)
	for _, original := range []struct{ name, source, declaration, opcode string }{
		{"dot", `TEXT floatdotsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), CX
	MOVQ b+16(FP), DX
	MOVUPS 0(CX), X0
	MOVUPS 0(DX), X1
	STC
	DPPS $0xf1, X0, X1
	MOVUPS X1, 0(AX)
	SETCS 16(AX)
	RET
`, "func floatdotsemantics(out,a,b *byte)", "dpps"},
		{"horizontal", "TEXT horizontal0(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nSTC\nHADDPS X0,X1\nVMOVUPS Z1,(AX)\nSETCS 64(AX)\nRET\n",
			"func horizontal0(out,a,b *byte)", "haddps"},
	} {
		t.Run(original.name, func(t *testing.T) {
			goAssemblerOracleOutput(t, "amd64", original.source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, original.source, original.declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil {
						t.Fatal("original initialized input/FLAGS/output program needs its missing native numerical continuation", err)
					}
					var native, reductions []string
					moves := 0
					for _, line := range strings.Split(ir, "\n") {
						if !strings.Contains(line, "asm sideeffect") {
							continue
						}
						native = append(native, strings.TrimSpace(line))
						if strings.Contains(line, `asm sideeffect "`+original.opcode+" ") {
							reductions = append(reductions, line)
						}
						if strings.Contains(line, `asm sideeffect "movups `) {
							moves++
						}
					}
					if len(reductions) != 1 || !strings.Contains(reductions[0], "~{fpsr}") || !strings.Contains(reductions[0], "~{memory}") ||
						original.name == "dot" && moves != 3 {
						t.Fatalf("original reduction/native moves lost exact effects: opcode=%s reductions=%d MOVUPS=%d\n%s", original.opcode, len(reductions), moves, strings.Join(native, "\n"))
					}
					t.Logf("original %s: %d whole reduction and %d native MOVUPS; exact IR effects:\n%s", original.opcode, len(reductions), moves, strings.Join(native, "\n"))
				})
			}
		})
	}
}

func TestX86PackedReductionCompleteTypedClassRegistration(t *testing.T) {
	rows := x86PackedReductionOracleRows()
	if len(rows) != 34 {
		t.Fatal("complete12-member/17-shape/34-format reduction inventory changed", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range rows {
			if arch == "386" && row.dot && !row.legacy {
				continue // Go's named frontend cannot represent four operands.
			}
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.row)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof {
					t.Fatal("complete numerical reduction class is absent from typed effects", known, err)
				}
				reads, writes := make(map[int]bool), make(map[int]bool)
				for _, operand := range effect.operands {
					if operand.width != int64(row.width) {
						t.Fatal("reduction borrowed another tuple or vector width", operand.width)
					}
					reads[operand.index] = reads[operand.index] || operand.read
					writes[operand.index] = writes[operand.index] || operand.write
				}
				if !reads[row.first] || !reads[row.second] || !writes[row.destination] ||
					!row.legacy && reads[row.destination] {
					t.Fatal("missing source/legacy old-destination dependency or invented VEX merge", effect)
				}
			})
		}
	}
}
