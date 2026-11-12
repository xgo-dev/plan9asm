package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86RawMaskCompareCompleteInputObjects(t *testing.T, bank string) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, suffix := goWordSize(target.arch), "Q"
			if word == 4 {
				suffix = "L"
			}
			var source, declarations strings.Builder
			count := 0
			for _, name := range []string{"VPCMPB", "VPCMPW", "VPCMPD", "VPCMPQ", "VPCMPUB", "VPCMPUW", "VPCMPUD", "VPCMPUQ"} {
				for _, masked := range []bool{false, true} {
					inputs := []string{bank + "3", "(AX)"}
					if strings.HasSuffix(name, "D") || strings.HasSuffix(name, "Q") {
						inputs = append(inputs, "broadcast")
					}
					for _, input := range inputs {
						op, mask, operand := name, "", input
						if input == "broadcast" {
							op, operand = op+".BCST", "(AX)"
						}
						if masked {
							mask = "K1,"
						}
						row := op + " $6," + operand + "," + bank + "4," + mask + "K2"
						// The original Go encoder supplies every byte. Low-register
						// physical mode32 rows are not its named arity limit.
						bytes := x86RawNumericalInstruction(t, "amd64", row)
						function := fmt.Sprint("RawCompare", count)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\n"+
							"MOV%s a+%d(FP),AX\nMOV%s b+%d(FP),BX\n"+
							"VMOVUPS (AX),Z3\nVMOVUPS (BX),Z4\nMOVL $-1431655766,CX\nKMOVD CX,K1\n"+
							"PUSH%s $0\nPOPF%s\n%s\nKMOVQ K2,(DI)\nPUSHF%s\nPOP%s CX\nMOV%s CX,64(DI)\nRET\n",
							function, 3*word, suffix, suffix, word, suffix, 2*word, suffix, suffix, bytes, suffix, suffix, suffix)
						fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b *[64]byte)\n", function)
						count++
					}
				}
			}
			if count != 40 {
				t.Fatal("complete raw compare input/broadcast/mask denominator changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func TestX86RawMaskCompareCompleteXInputObjects(t *testing.T) {
	x86RawMaskCompareCompleteInputObjects(t, "X")
}
func TestX86RawMaskCompareCompleteYInputObjects(t *testing.T) {
	x86RawMaskCompareCompleteInputObjects(t, "Y")
}
func TestX86RawMaskCompareCompleteZInputObjects(t *testing.T) {
	x86RawMaskCompareCompleteInputObjects(t, "Z")
}
