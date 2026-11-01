package plan9asm

import (
	"strings"
	"testing"
)

func TestGoX86NumericalSBVectorReadCompleteTypedFamily(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for op, spec := range x86AESSpecs {
			widths := []int{16}
			if spec.vector && spec.operation < x86AESInverseMix && arch == "amd64" {
				widths = []int{16, 32, 64}
			}
			for _, width := range widths {
				args := "·mutable+16(SB), X0"
				if spec.operation == x86AESKeyAssist {
					args = "$7, " + args
				} else if spec.vector && spec.operation < x86AESInverseMix {
					reg := map[int]string{16: "X0", 32: "Y0", 64: "Z0"}[width]
					args = "·mutable+16(SB), " + reg + ", " + reg
				}
				t.Run(arch+"/"+string(op)+"/"+args, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-0\n"+string(op)+" "+args+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					operand, bytes, valid := x86NumericalSBReadShape(file.Funcs[0].Instrs[1], arch)
					wantOperand := 0
					if spec.operation == x86AESKeyAssist {
						wantOperand = 1
					}
					if !valid || operand != wantOperand || bytes != int64(width) {
						t.Fatal("typed mutable AES read is absent", operand, bytes, valid)
					}
				})
			}
		}
		for op, spec := range x86PackedLogicalSpecs {
			legacy := spec.encoding == x86PackedLogicalLegacyFP || spec.encoding == x86PackedLogicalLegacyInteger
			widths := []int{16}
			if !legacy {
				widths = []int{16, 32}
				if spec.encoding != x86PackedLogicalVEX {
					widths = append(widths, 64)
				}
			}
			for _, width := range widths {
				reg := map[int]string{16: "X0", 32: "Y0", 64: "Z0"}[width]
				args := "·mutable(SB), " + reg
				if !legacy {
					args += ", " + reg
				}
				t.Run(arch+"/"+string(op)+"/"+args, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-0\n"+string(op)+" "+args+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					operand, bytes, valid := x86NumericalSBReadShape(file.Funcs[0].Instrs[1], arch)
					if !valid || operand != 0 || bytes != int64(width) {
						t.Fatal("typed mutable logical read is absent", operand, bytes, valid)
					}
				})
			}
		}
		for _, source := range []string{
			"AESENC $·mutable(SB), X0", "AESENC ·mutable(SB), M0", "AESENC ·mutable(SB), X8",
			"PXOR X0, ·mutable(SB)", "PXOR ·mutable(SB), M0", "VAESENC.Z ·mutable(SB), X0, X0",
			"VPXORD.Z ·mutable(SB), X0, X0", "VPXORD.BCST X0, X0, X0",
		} {
			if arch == "amd64" && strings.HasSuffix(source, "X8") {
				continue
			}
			file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-0\n"+source+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, valid := x86NumericalSBReadShape(file.Funcs[0].Instrs[1], arch); valid {
				t.Fatal("unbound/invalid vector role acquired a numerical read", arch, source)
			}
		}
	}
}
