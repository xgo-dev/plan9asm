package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalScalarFloatIntegerAssembly(name, operation string) string {
	return fmt.Sprintf(`TEXT ·%s(SB),4,$64-16
MOVQ a+0(FP),AX
MOVQ AX,0(SP)
MOVQ AX,16(SP)
MOVQ AX,24(SP)
VMOVUPS 16(SP),X1
VMOVUPS 16(SP),X17
MOVQ $2,BP
%s
MOVQ AX,ret+8(FP)
RET
`, name, operation)
}

func TestGoAMD64FixedLocalScalarFloatIntegerObjects(t *testing.T) {
	operations := []string{
		"CVTTSS2SL 4(SP),AX",
		"CVTSD2SQ 0(SP),AX",
		"VCVTSS2SI 12(SP)(BP*2),AX",
		"VCVTTSD2USIQ 12(SP)(BP*2),AX",
		"VCVTSS2USIL X17,AX",
		"VCVTSD2USIL.RZ_SAE X17,AX",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalScalarFloatIntegerAssembly(name, operation))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalScalarFloatIntegerOfficialForms(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	var originalVector []string
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		vector := strings.HasPrefix(name, "V")
		register := "X1"
		if vector {
			register = "X17"
		}
		for _, source := range []string{"12(SP)(BP*2)", register} {
			operation := name + " " + source + ",AX"
			if vector {
				originalVector = append(originalVector, operation)
			}
			file, err := Parse(ArchAMD64, fixedLocalScalarFloatIntegerAssembly("Value", operation))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
				t.Errorf("%s: initialized fixed frame failed: %v", operation, err)
			}
		}
	}
	if len(originalVector) != 32 {
		t.Fatal("incomplete official scalar vector conversion inventory", len(originalVector))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(originalVector, "\n")+"\nRET")
	if len(pcs) != len(originalVector)+1 {
		t.Fatal("missing original vector conversion boundaries", pcs)
	}
	for index, operation := range originalVector {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Errorf("%s: actual Go encoding %x has boundary %d/%d: %v", operation, encoding, length, len(encoding), err)
		}
	}
}

func TestGoAMD64FixedLocalScalarFloatIntegerInputBounds(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		valid     bool
	}{
		{"VCVTSS2USIL 4(SP),AX", true},
		{"VCVTSD2USIL 4(SP),AX", false},
		{"VCVTSS2USIL X2,AX", false},
		{"VCVTSS2USIL 4(SP),SP", false},
	} {
		t.Run(row.operation, func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixedLocalScalarFloatIntegerAssembly("Value", row.operation))
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
