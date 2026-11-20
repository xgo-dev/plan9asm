package plan9asm

import (
	"strings"
	"testing"
)

// Measure complete analysis, lowering and LLVM verification for the four
// physical-source families. Parsing stays outside the timer; independent
// family tests cover numerical values, native faults and source permissions.
func BenchmarkX86PackedPhysicalTranslation(b *testing.B) {
	for _, family := range x86PackedPhysicalTestFamilies() {
		for _, name := range strings.Fields(family.names) {
			b.Run(name, func(b *testing.B) {
				operands := "X0,X1"
				if strings.HasPrefix(name, "V") {
					operands = "Y0,Y1,Y2"
				}
				source := "TEXT binary(SB),4,$0-0\n" +
					"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" +
					strings.Repeat(name+" "+operands+"\n", 32) + "RET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					b.Fatal(err)
				}
				options := Options{
					Goarch:       "amd64",
					TargetTriple: "x86_64-unknown-linux-gnu",
					Sigs:         map[string]FuncSig{"binary": {Name: "binary", Ret: Void}},
				}
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
}
