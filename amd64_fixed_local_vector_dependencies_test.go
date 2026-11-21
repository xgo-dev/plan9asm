package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalVectorDependencyAssembly(t *testing.T, name, operation string, omit Reg) string {
	t.Helper()
	if strings.HasPrefix(operation, "V") {
		return fixedLocalVectorStackAssembly(t, name, operation, "", omit)
	}
	ins := x86ScalarLaneInstruction(t, operation)
	destination := ins.Args[len(ins.Args)-1].Reg
	body := fmt.Sprintf("MOVUPS 64(BP),%s\n%s\nMOVUPS %s,128(BP)", destination, operation, destination)
	return strings.Replace(fixedLocalPackedAssembly(body), "·Value(SB)", "·"+name+"(SB)", 1)
}

func TestGoAMD64FixedLocalVectorDependenciesObjects(t *testing.T) {
	operations := []string{
		"PABSD 64(BP),X2",
		"PSIGNW 64(BP),X2",
		"SHUFPD $3,64(BP),X2",
		"VPABSQ.BCST.Z 120(SP),K1,Y7",
		"VPSIGND 17(SP)(BP*2),Y2,Y7",
		"VSHUFPS $177,17(SP)(BP*2),Z11,K2,Z19",
		"VPTERNLOGQ.BCST.Z $231,120(SP),Z17,K3,Z19",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorDependencyAssembly(t, name, operation, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalVectorDependenciesOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var memoryOperations, vectorOperations []string
	seen := make(map[string]bool)
	rowCount := 0
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedAbsRows,
		goasmrules.X86PackedSignRows,
		goasmrules.X86TwoSourceImmediateShuffleRows,
		goasmrules.X86LeadingImmediateVectorRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if !strings.Contains(row.Opcode, "ABS") && !strings.Contains(row.Opcode, "SIGN") &&
				!strings.Contains(row.Opcode, "SHUF") && !strings.HasPrefix(row.Opcode, "VPTERNLOG") {
				continue
			}
			rowCount++
			for _, witness := range row.Witnesses {
				operation := witness.Instruction
				address := "17(SP)(BP*2)"
				if witness.Generation == "legacy" {
					address = "64(BP)"
				}
				if witness.Memory {
					operation = strings.Replace(operation, "(AX)", address, 1)
					if operation == witness.Instruction {
						t.Fatalf("%s lacks a memory operand: %s", row.ID, operation)
					}
				}
				if seen[operation] {
					continue
				}
				seen[operation] = true
				if witness.Generation != "legacy" {
					vectorOperations = append(vectorOperations, operation)
				}
				if witness.Memory {
					name := fmt.Sprintf("Value%d", len(memoryOperations))
					assembly.WriteString(fixedLocalVectorDependencyAssembly(t, name, operation, ""))
					memoryOperations = append(memoryOperations, operation)
				}
			}
		}
	}
	t.Logf("selected %d official rows, %d VEX/EVEX witnesses and %d stack forms", rowCount, len(vectorOperations), len(memoryOperations))
	if rowCount != 72 || len(vectorOperations) != 230 || len(memoryOperations) != 150 {
		t.Fatal("incomplete ABS, SIGN, SHUF and TERNLOG inventory")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(vectorOperations, "\n")+"\nRET")
	if len(pcs) != len(vectorOperations)+1 {
		t.Fatal("missing original byte boundaries")
	}
	for index, operation := range vectorOperations {
		encoding := code[pcs[index]:pcs[index+1]]
		if length, err := x86NumericalVectorBoundary(encoding, 64); err != nil || length != len(encoding) {
			t.Fatalf("%s: original bytes %x: boundary %d/%d: %v", operation, encoding, length, len(encoding), err)
		}
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil || len(file.Funcs) != len(memoryOperations) {
		t.Fatal("incomplete parsed stack functions", err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, fn := range file.Funcs {
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatalf("%s: initialized stack form: %v", memoryOperations[index], err)
		}
	}
}

func TestGoAMD64FixedLocalVectorDependenciesBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		omit      Reg
		valid     bool
	}{
		{"PABSD 65(BP),X2", "", false},
		{"SHUFPD $3,65(BP),X2", "", false},
		{"VPABSD.BCST 124(SP),K1,Y3", "Z3", false},
		{"VPABSD.BCST.Z 124(SP),K1,Y3", "Z3", true},
		{"VSHUFPS.Z $0,124(SP),Z2,K1,Z3", "Z3", false},
		{"VSHUFPS.BCST.Z $0,124(SP),Z2,K1,Z3", "Z3", true},
		{"VPTERNLOGD.Z $0,124(SP),Z2,K1,Z3", "Z3", false},
		{"VPTERNLOGD.BCST.Z $0,124(SP),Z2,K1,Z3", "Z3", true},
	} {
		t.Run(row.operation, func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixedLocalVectorDependencyAssembly(t, "Value", row.operation, row.omit))
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}
}
