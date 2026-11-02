package plan9asm

import (
	"strings"
	"testing"
)

func TestX86ScalarShiftEmitterRetainsBMI2FamilyBoundary(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"SARXL CX,BX,AX", "SARXQ CX,BX,AX",
			"SHLXL CX,BX,AX", "SHLXQ CX,BX,AX",
			"SHRXL CX,BX,AX", "SHRXQ CX,BX,AX",
			"RORXL $7,BX,AX", "RORXQ $7,BX,AX",
		} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			original := file.Funcs[0].Instrs[1]
			for _, ins := range []Instr{original, {Op: original.Op}, {Op: "SHLQ", Args: original.Args}} {
				t.Run(arch+"/"+row+"/"+string(ins.Op), func(t *testing.T) {
					var output strings.Builder
					output.WriteString("existing IR\n")
					ctx := amd64Ctx{b: &output, goarch: arch, tmp: 7}
					known, terminated, err := ctx.lowerScalarShiftRotate(original.Op, ins)
					if known || terminated || err != nil || ctx.tmp != 7 || output.String() != "existing IR\n" {
						t.Fatalf("BMI2 reached the Group2 emitter: known=%t terminal=%t error=%v tmp=%d IR=%q", known, terminated, err, ctx.tmp, output.String())
					}
				})
			}
		}
	}
}
