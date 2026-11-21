package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalDotProductOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86PackedEVEXBinaryRemainderRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations, stackForms []string
	seen := make(map[string]bool)
	rowCount := 0
	for _, row := range rows {
		if !strings.HasPrefix(row.Opcode, "VPDP") {
			continue
		}
		rowCount++
		for _, witness := range row.Witnesses {
			operation := witness.Instruction
			if witness.Memory {
				if !strings.Contains(operation, "(AX)") {
					t.Fatalf("%s: missing base operand in %s", row.ID, operation)
				}
				operation = strings.Replace(operation, "(AX)", "17(SP)(BP*2)", 1)
			}
			if seen[operation] {
				continue
			}
			seen[operation] = true
			operations = append(operations, operation)
			if witness.Memory {
				name := fmt.Sprintf("Value%d", len(stackForms))
				assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
				stackForms = append(stackForms, operation)
			}
		}
	}
	t.Logf("%d official rows, %d original encodings, %d fixed-stack forms", rowCount, len(operations), len(stackForms))
	if rowCount != 24 || len(operations) != 108 || len(stackForms) != 72 {
		t.Fatal("incomplete official integer dot-product inventory")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go instruction boundaries")
	}
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		if length, err := x86NumericalVectorBoundary(encoding, 64); err != nil || length != len(encoding) {
			t.Fatalf("%s: original bytes %x: boundary %d/%d: %v", operation, encoding, length, len(encoding), err)
		}
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil || len(file.Funcs) != len(stackForms) {
		t.Fatal("incomplete parsed dot-product stack functions", err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, fn := range file.Funcs {
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatalf("%s: initialized stack operands: %v", stackForms[index], err)
		}
	}
}

func TestGoAMD64FixedLocalDotProductObjects(t *testing.T) {
	operations := []string{
		"VPDPBUSD 17(SP)(BP*2),X2,K1,X3",
		"VPDPBUSDS.Z 17(SP)(BP*2),Y2,K1,Y3",
		"VPDPWSSD.BCST 124(SP),Z17,Z19",
		"VPDPWSSDS.BCST.Z 124(SP),Z17,K1,Z19",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalDotProductAccumulator(t *testing.T) {
	operation := "VPDPWSSDS.BCST.Z 124(SP),Z2,K1,Z3"
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name string
		omit Reg
	}{
		{"complete", ""},
		{"missing accumulator", "Z3"},
		{"missing multiplicand", "Z2"},
		{"missing mask", "K1"},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixedLocalVectorStackAssembly(t, "Value", operation, "", row.omit))
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.omit == "" && err != nil || row.omit != "" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("omitted %q: %v", row.omit, err)
			}
		})
	}
}
