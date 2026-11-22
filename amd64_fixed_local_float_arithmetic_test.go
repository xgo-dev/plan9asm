package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalCOMIAssembly(name, operation, seed string) string {
	return fmt.Sprintf("TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\nMOVQ AX,120(SP)\n%s\n%s\n"+
		"MOVQ $0,AX\nSETCS AL\nMOVQ AX,ret+8(FP)\nRET\n", name, seed, operation)
}

func TestGoAMD64FixedLocalCOMIOfficialMemoryRows(t *testing.T) {
	var assembly, declarations strings.Builder
	count := 0
	for _, op := range x86COMIOracleNames() {
		operands := []struct{ memory, register, seed string }{
			{"120(SP)", "X2", "PXOR X2,X2"},
		}
		if strings.HasPrefix(op, "V") {
			operands = append(operands, struct{ memory, register, seed string }{
				"120(SP)", "X19", "VPXORD X19,X19,X19",
			})
		}
		if op == "VUCOMISD" {
			// Replay the original EVEX form from the Go assembler corpus.
			operands[1].memory = "(SP)"
			operands[1].register = "X31"
			operands[1].seed = "MOVQ AX,(SP)\nVPXORD X31,X31,X31"
		}
		for _, row := range operands {
			name := fmt.Sprintf("Value%d", count)
			operation := fmt.Sprintf("%s %s,%s", op, row.memory, row.register)
			assembly.WriteString(fixedLocalCOMIAssembly(name, operation, row.seed))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			count++
		}
	}
	if count != 12 {
		t.Fatal("incomplete legacy, VEX and EVEX compare matrix", count)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalCOMIDependencies(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		instruction, seed string
		valid             bool
	}{
		{"COMISS 124(SP),X2", "PXOR X2,X2", true},
		{"UCOMISD 124(SP),X2", "PXOR X2,X2", false},
		{"VCOMISD 120(SP),X2", "PXOR X2,X2", true},
		{"VUCOMISD 120(SP),X2", "", false},
		{"VUCOMISD (SP),X2", "PXOR X2,X2", false},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			source := fixedLocalCOMIAssembly("Value", row.instruction, row.seed)
			file, err := Parse(ArchAMD64, source)
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

func TestGoAMD64FixedLocalFloatArithmeticOriginalObjects(t *testing.T) {
	operations := []string{
		"VMAXPS -17(CX)(AX*8),X7,K5,X10",
		"VMAXPS (SP),Z19,K1,Z21",
		"VMAXSD 7(SP)(DI*8),X5,K4,X30",
		"VMINSS 7(SP)(DI*8),X5,K4,X30",
		"VSQRTPS 7(SP)(DI*8),K4,Y30",
		"VSQRTPS 7(SP)(DI*8),K4,X30",
		"VSQRTPD.BCST.Z 120(SP),K4,Z30",
		"VSQRTSS 7(SP)(DI*8),X5,K4,X30",
		"VADDPD.BCST.Z 120(SP),Z5,K4,Z30",
		"VDIVSS.Z 124(SP),X5,K4,X30",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		setup := "LEAQ 48(SP),CX\nMOVQ $1,AX\nMOVQ $1,DI\n"
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalFloatArithmeticOfficialMemoryRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := goasmrules.X86AVXFloatBinaryRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	special, err := goasmrules.X86SpecialVectorStateRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range special {
		switch row.Opcode {
		case "VSQRTPS", "VSQRTPD", "VSQRTSS", "VSQRTSD":
			binary = append(binary, row)
		}
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	var source strings.Builder
	var operations []string
	seen := make(map[string]bool)
	members := make(map[string]bool)
	for _, row := range binary {
		members[row.Opcode] = true
		for _, witness := range row.Witnesses {
			if !witness.Memory {
				continue
			}
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			if operation == witness.Instruction {
				t.Fatalf("row %s lacks its memory operand: %s", row.ID, witness.Instruction)
			}
			if !seen[operation] {
				source.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", len(operations)), operation, "", ""))
				operations = append(operations, operation)
				seen[operation] = true
			}
		}
	}
	t.Logf("%d opcode names, %d rows and %d distinct memory spellings", len(members), len(binary), len(operations))
	if len(members) != 28 || len(binary) != 154 || len(operations) != 336 {
		t.Fatal("missing original floating arithmetic inventory")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil || len(file.Funcs) != len(operations) || len(pcs) != len(operations)+1 {
		t.Fatal("missing original memory instruction or parsed function", err, len(pcs))
	}
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Fatalf("%s: wrong original instruction boundary for %x: %d, %v", operation, encoding, length, err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[index], sig); err != nil {
			t.Fatalf("%s: initialized frame rejected: %v", operation, err)
		}
	}
}

func TestGoAMD64FixedLocalFloatArithmeticDependencies(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		instruction string
		omit        Reg
		valid       bool
	}{
		{"VMAXSS.Z 124(SP),X4,K1,X5", "Z5", true},
		{"VMAXSS 124(SP),X4,K1,X5", "Z5", false},
		{"VMAXSD.Z 124(SP),X4,K1,X5", "", false},
		{"VMAXPS.BCST 124(SP),Z4,K1,Z5", "", true},
		{"VMAXPS 124(SP),Z4,K1,Z5", "", false},
		{"VSQRTSS.Z 124(SP),X4,K1,X5", "Z4", false},
		{"VSQRTSS.Z 124(SP),X4,K1,X5", "Z5", true},
		{"VSQRTPS.Z 64(SP),K1,Z5", "Z5", true},
		{"VSQRTPS 64(SP),K1,Z5", "Z5", false},
		{"VSQRTPS.Z 64(SP),K1,Z5", "K1", false},
	} {
		label := fmt.Sprintf("%s/omit=%s", row.instruction, row.omit)
		t.Run(label, func(t *testing.T) {
			source := fixedLocalVectorStackAssembly(t, "Value", row.instruction, "", row.omit)
			file, err := Parse(ArchAMD64, source)
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
