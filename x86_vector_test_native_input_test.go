package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86VectorTestInputRows() []string {
	return []string{
		"PTEST (SI),X1",
		"VPTEST (SI),X1", "VPTEST (SI),Y1",
		"VTESTPD (SI),X1", "VTESTPD (SI),Y1",
		"VTESTPS (SI),X1", "VTESTPS (SI),Y1",
	}
}

func TestX86VectorTestPairedNativeCompleteFamilyFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, suffix := goWordSize(target.arch), "Q"
			if word == 4 {
				suffix = "L"
			}
			for _, raw := range []bool{false, true} {
				var source, declarations strings.Builder
				for index, row := range x86VectorTestInputRows() {
					operation := row
					if raw {
						operation = x86RawNumericalInstruction(t, target.arch, row)
					}
					name := fmt.Sprint("VectorTest", index)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\n"+
						"MOV%s input+%d(FP),SI\nMOV%s old+%d(FP),BX\nVMOVUPS (BX),Y1\n"+
						"PUSH%s $0\nPOPF%s\n%s\nPUSHF%s\nPOP%s AX\nMOV%s AX,(DI)\nRET\n",
						name, 3*word, suffix, suffix, word, suffix, 2*word, suffix, suffix,
						operation, suffix, suffix, suffix)
					fmt.Fprintf(&declarations, "func %s(out *[16]byte,input,old *[32]byte)\n", name)
				}
				x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
			}
		})
	}
}

func TestX86VectorTestDeadInputsCannotBorrowVoidOrBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86VectorTestInputRows() {
			for _, raw := range []bool{false, true} {
				operation := row
				if raw {
					operation = x86RawNumericalInstruction(t, target.arch, row)
				}
				source := "TEXT ·Value(SB),4,$0\n" + operation + "\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("vector test borrowed native inputs from Void or unused bool", row, raw,
								target.triple, declaration, api, err)
						}
					}
				}
			}
		}
	}
}
