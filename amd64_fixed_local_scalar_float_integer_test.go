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

func fixedLocalScalarFloatIntegerStackResult(name, operation string) string {
	return fixedLocalScalarFloatIntegerAssembly(name,
		"MOVQ SP,R11\n"+operation+"\nMOVQ SP,AX\nMOVQ R11,SP")
}

const fixedLocalFloatIntegerRegisterOnly = `TEXT ·%s(SB),4,$64-16
MOVQ a+0(FP),AX
MOVQ AX,X1
MOVQ SP,R11
CVTSS2SL X1,SP
MOVQ SP,AX
MOVQ R11,SP
MOVQ AX,ret+8(FP)
RET
`

func TestGoAMD64FixedLocalScalarFloatIntegerStackResultObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	count := 0
	add := func(source string, stackResult bool) {
		name := fmt.Sprintf("Value%d", count)
		if stackResult {
			assembly.WriteString(fixedLocalScalarFloatIntegerStackResult(name, source))
		} else {
			assembly.WriteString(fixedLocalScalarFloatIntegerAssembly(name, source))
		}
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		count++
	}
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		for _, source := range []string{"12(SP)(BP*2)", "X1"} {
			add(fmt.Sprintf("%s %s,SP", name, source), true)
		}
		if strings.HasPrefix(name, "V") {
			add(fmt.Sprintf("%s X17,SP", name), true)
		}
	}

	// Use the original Go operands even when the same native register supplies
	// both base and index. The input is the caller's complete machine word.
	for _, name := range []string{"VCVTSD2USIL", "VCVTTSS2USIL"} {
		add("MOVQ a+0(FP),R15\n"+name+" 99(R15)(R15*4),R14\nMOVQ R14,AX", false)
		add("MOVQ a+0(FP),R15\n"+name+" 99(R15)(R15*4),SP", true)
		add("MOVQ a+0(FP),DX\n"+name+" 15(DX),SP", true)
	}
	add("VCVTSS2USIL 17(SP)(BP*1),SP", true)
	add("LEAQ 32(SP),CX\nMOVQ $1,DX\nMOVQ AX,33(SP)\nVCVTSS2USIL -7(CX)(DX*8),SP", true)
	if count != 72 {
		t.Fatal("incomplete scalar float-to-integer stack-result matrix", count)
	}
	name := fmt.Sprintf("Value%d", count)
	assembly.WriteString(fmt.Sprintf(fixedLocalFloatIntegerRegisterOnly, name))
	fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	count++
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalScalarFloatIntegerStackResultBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	base := fixedLocalScalarFloatIntegerStackResult("Value", "CMPQ AX,$0\nVCVTSS2USIL 4(SP),SP")
	for _, row := range []struct {
		name, old, replacement string
		valid                  bool
	}{
		{"restored", "", "", true},
		{"dead result", "MOVQ SP,AX\n", "", true},
		{"uninitialized conversion", "4(SP),SP", "8(SP),SP", false},
		{"missing restore", "MOVQ R11,SP\n", "", false},
		{"numerical restore", "MOVQ R11,SP", "MOVQ AX,SP", false},
		{"clobbered saved SP", "MOVQ SP,AX", "MOVQ SP,AX\nMOVQ $0,R11", false},
		{"load through temporary SP", "MOVQ SP,AX", "MOVQ 0(SP),AX", false},
		{"load through saved SP", "MOVQ SP,AX", "MOVQ 0(R11),AX", false},
		{"access to FP slot", "MOVQ SP,AX", "MOVQ a+0(FP),AX", false},
		{"call with temporary SP", "MOVQ SP,AX", "CALL ·External(SB)\nMOVQ SP,AX", false},
		{"branch restores both paths", "MOVQ SP,AX\nMOVQ R11,SP", "JEQ restore\nMOVQ SP,AX\nrestore:\nMOVQ R11,SP", true},
		{"branch bypasses restore", "MOVQ R11,SP", "JEQ exit\nMOVQ R11,SP\nexit:", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := base
			if row.old != "" {
				source = strings.Replace(source, row.old, row.replacement, 1)
			}
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

func TestGoAMD64FixedLocalScalarFloatIntegerStackResultNeedsFrameBinding(t *testing.T) {
	source := fmt.Sprintf(fixedLocalFloatIntegerRegisterOnly, "Value")
	for _, body := range []string{source, strings.Replace(source, "MOVQ R11,SP\n", "", 1)} {
		file, err := Parse(ArchAMD64, body)
		if err != nil {
			t.Fatal(err)
		}
		if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
			t.Fatal("register-only conversion to SP must be independently checked")
		}
	}
}
