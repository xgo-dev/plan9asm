package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalFloatingHelperOriginalObjects(t *testing.T) {
	operations := []string{
		"VGETEXPSS.Z 124(SP),X17,K1,X19",
		"VGETMANTPD.BCST $13,120(SP),K2,Z20",
		"VSCALEFPS 17(SP)(BP*2),Z17,K2,Z20",
		"VFIXUPIMMSS.Z $7,124(SP),X17,K2,X19",
		"VRANGEPS $7,17(SP)(BP*2),Y17,K2,Y19",
		"VRNDSCALESD $7,120(SP),X17,K2,X19",
		"VREDUCEPS $13,17(SP)(BP*2),K2,Z19",
		"VRCP28SD 120(SP),X17,K2,X19",
		"VEXP2PD.BCST 120(SP),K2,Z19",
		"VFPCLASSSD $255,120(SP),K3,K3",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalFloatingHelperOfficialMemoryRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86FloatingHelperRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations, memoryOperations []string
	seen := make(map[string]bool)
	members := make(map[string]bool)
	for _, row := range rows {
		members[row.Opcode] = true
		for _, witness := range row.Witnesses {
			operation := witness.Instruction
			if witness.Memory {
				operation = strings.Replace(operation, "(AX)", "17(SP)(BP*2)", 1)
				if operation == witness.Instruction {
					t.Fatalf("row %s has no memory operand: %s", row.ID, operation)
				}
			}
			if seen[operation] {
				continue
			}
			operations = append(operations, operation)
			seen[operation] = true
			if witness.Memory {
				name := fmt.Sprintf("Value%d", len(memoryOperations))
				assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
				memoryOperations = append(memoryOperations, operation)
			}
		}
	}
	t.Logf("selected %d mnemonics, %d Go rows, %d original encodings and %d stack forms",
		len(members), len(rows), len(operations), len(memoryOperations))
	if len(members) != 54 || len(rows) != 180 || len(memoryOperations) != 482 {
		t.Fatal("incomplete floating-helper inventory")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go floating-helper encodings", len(pcs), len(operations))
	}
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Fatalf("%s: original bytes %x failed to bind: %d, %v", operation, encoding, length, err)
		}
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != len(memoryOperations) {
		t.Fatal("missing parsed floating-helper functions", len(file.Funcs), len(memoryOperations))
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, fn := range file.Funcs {
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatalf("%s: initialized frame did not bind: %v", memoryOperations[index], err)
		}
	}
}

func TestGoAMD64FixedLocalFloatingHelperControlBoundaries(t *testing.T) {
	operations := []string{
		"VSCALEFPS.RZ_SAE.Z Z20,Z21,K1,Z22",
		"VSCALEFSD.RU_SAE X20,X21,X22",
		"VGETEXPPD.SAE Z20,K1,Z22",
		"VGETMANTSS.SAE $7,X20,X21,X22",
		"VFPCLASSPSY $7,table(SB),K1,K2",
		"VREDUCEPS.BCST $7,table(SB),K1,Z22",
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go control boundaries", pcs)
	}
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Errorf("%s: boundary %d/%d: %v", operation, length, len(encoding), err)
		}
		if _, err := x86NumericalVectorBoundary(encoding[:len(encoding)-1], 64); err == nil {
			t.Errorf("%s: truncated final byte acquired a boundary", operation)
		}
		changed := append([]byte(nil), encoding...)
		changed[2] &^= 4
		if _, err := x86NumericalVectorBoundary(changed, 64); err == nil {
			t.Errorf("%s: a cleared fixed bit acquired a boundary", operation)
		}
	}
}

func TestGoAMD64FixedLocalFloatingHelperTupleAndInputs(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation string
		omit            Reg
		valid           bool
	}{
		{"zeroing ignores old destination", "VGETEXPSS.Z 124(SP),X17,K1,X19", "Z19", true},
		{"merging needs old destination", "VGETEXPSS 124(SP),X17,K1,X19", "Z19", false},
		{"fixup zeroing still reads old destination", "VFIXUPIMMSS.Z $7,124(SP),X17,K1,X19", "Z19", false},
		{"scalar output needs upper input", "VGETEXPSS.Z 124(SP),X17,K1,X19", "Z17", false},
		{"double needs eight source bytes", "VGETEXPSD 124(SP),X17,K1,X19", "", false},
		{"broadcast needs only one element", "VGETMANTPD.BCST $7,120(SP),K1,Z19", "", true},
		{"packed read needs every possible byte", "VGETMANTPD $7,120(SP),K1,Z19", "", false},
		{"class mask result defines an uninitialized destination", "VFPCLASSSD $7,120(SP),K1,K3", "K3", true},
		{"class alias needs the original input mask", "VFPCLASSSD $7,120(SP),K1,K1", "K1", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalVectorStackAssembly(t, "Value", row.operation, "", row.omit)
			file, err := Parse(ArchAMD64, assembly)
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
