package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86AESPairedNativeCompleteFamilyFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, suffix := goWordSize(target.arch), "Q"
			if word == 4 {
				suffix = "L"
			}
			for _, raw := range []bool{false, true} {
				var source, declarations strings.Builder
				count := 0
				for _, name := range x86AESOracleNames {
					banks := []string{"X"}
					if strings.HasPrefix(name, "V") && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
						banks = append(banks, "Y", "Z")
					}
					for _, bank := range banks {
						operation, destination := x86AESOracleRow(name, "(SI)", bank)
						if raw {
							operation = x86RawNumericalInstruction(t, target.arch, operation)
						}
						function := fmt.Sprint("AESRead", count)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\n"+
							"MOV%s input+%d(FP),SI\nMOV%s old+%d(FP),BX\nVMOVUPS (BX),Z1\nVMOVUPS (BX),Z2\n"+
							"PUSH%s $0\nPOPF%s\n%s\nVMOVUPS Z%d,(DI)\nPUSHF%s\nPOP%s AX\nMOV%s AX,64(DI)\nRET\n",
							function, 3*word, suffix, suffix, word, suffix, 2*word, suffix, suffix, operation,
							destination, suffix, suffix, suffix)
						fmt.Fprintf(&declarations, "func %s(out *[80]byte,input,old *[64]byte)\n", function)
						count++
					}
				}
				if count != 20 {
					t.Fatal("complete AES/VAES round, inverse-mix and key-assist inventory changed", count)
				}
				x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
			}
		})
	}
}

func TestX86AESDeadNativeInputsCannotBorrowVoidOrBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range x86AESOracleNames {
			operation, _ := x86AESOracleRow(name, "(SI)", "X")
			for _, raw := range []bool{false, true} {
				instruction := operation
				if raw {
					instruction = x86RawNumericalInstruction(t, target.arch, operation)
				}
				source := "TEXT ·Value(SB),4,$0\n" + instruction + "\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("AES borrowed native inputs from Void or unused bool", name, raw, target.triple, declaration, api, err)
						}
					}
				}
			}
		}
	}
}
