package plan9asm

import (
	"strings"
	"testing"
)

// Keep parsing outside the timer, but include source analysis, lowering and
// LLVM verification. These register-only kernels need no native x86 hardware.
// The independent family tests own memory faults and executable semantics.
func BenchmarkX86PackedBinaryTranslation(b *testing.B) {
	for _, row := range []string{
		"PSUBL X0,X1",
		"VPSUBD Y0,Y1,Y2",
		"VPSUBSW.Z Z0,Z1,K1,Z2",
		"PMULLD X0,X1",
		"VPMULLD Y0,Y1,Y2",
		"VPMULLQ.Z Z0,Z1,K1,Z2",
		"PADDL X0,X1",
		"VPADDD Y0,Y1,Y2",
		"VPADDSW.Z Z0,Z1,K1,Z2",
	} {
		b.Run(row, func(b *testing.B) {
			source := "TEXT binary(SB),4,$0-0\n" +
				"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" +
				"MOVQ $5,AX\nKMOVQ AX,K1\n" +
				strings.Repeat(row+"\n", 32) + "RET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				b.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"binary": {Name: "binary", Ret: Void}}}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := Translate(file, options); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
