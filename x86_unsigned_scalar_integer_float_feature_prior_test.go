package plan9asm

import "testing"

// Go's complete unsigned _yvcvtusi2sdl family is EVEX-only. Intel SDM
// VCVTUSI2SD/SS lists AVX512F (not VL) in both physical modes; non-64-bit
// mode ignores W1. These are object/feature observations, not initialized
// public inputs or an actual AVX512 execution claim.
func TestX86UnsignedScalarIntegerFloatActualGoFeaturePrior(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op string
			pp byte
			w  byte
		}{
			{"VCVTUSI2SDL", 3, 0}, {"VCVTUSI2SDQ", 3, 1},
			{"VCVTUSI2SSL", 2, 0}, {"VCVTUSI2SSQ", 2, 1},
		} {
			for _, operand := range []string{"AX", "(BX)"} {
				instruction := row.op + " " + operand + ",X0,X1"
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					source := "TEXT physical(SB),4,$0-0\n" + instruction + "\nRET\n"
					code := x86OrderingHintGoBytes(t, arch, source)
					if len(code) != 7 || code[0] != 0x62 || code[1]&7 != 1 ||
						code[2]&3 != row.pp || code[2]>>7 != row.w || code[4] != 0x7b || code[6] != 0xc3 {
						t.Fatalf("actual %s unsigned scalar EVEX prefix/opcode changed: %x", arch, code)
					}
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					form, known, err := x86UnsignedIntegerFloatProperties(file.Funcs[0].Instrs[1], arch)
					width := 32
					if arch == "amd64" && row.w != 0 {
						width = 64
					}
					if !known || err != nil || form.sourceBits != width {
						t.Fatal("actual named unsigned row lost its physical mode width", form, known, err)
					}
					if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0]); got != "+avx512f" {
						t.Fatal("actual EVEX unsigned source lost its isolated scalar F profile", instruction, arch, got)
					}
				})
			}
			t.Run(arch+"/"+row.op+"/invalid-zeroing", func(t *testing.T) {
				instruction := row.op + ".Z AX,X0,X1"
				source := "TEXT invalid(SB),4,$0-0\n" + instruction + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0]); got != "" {
					t.Fatal("Go-rejected unsigned suffix acquired a feature profile", instruction, arch, got)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				assertX86ScalarIntegerFloatRejected(t, arch, triple, instruction)
			})
		}
	}
}
