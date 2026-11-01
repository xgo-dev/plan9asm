package plan9asm

import (
	"strings"
	"testing"
)

// Use identical initialized scalar input to isolate the text-fallback cost.
// The direct case must gain no demand scan or catalog lookup. Existing packed
// binary/physical and baseline-GP benchmarks retain their original case IDs.
func BenchmarkX86PreludeTranslation(b *testing.B) {
	for _, annotate := range []bool{false, true} {
		name := "direct"
		if annotate {
			name = "annotated-fallback"
		}
		b.Run(name, func(b *testing.B) {
			source := "TEXT scalar(SB),4,$0-0\n" + strings.Repeat("MOVL $7,AX\n", 64) + "RET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				b.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", AnnotateSource: annotate,
				Sigs: map[string]FuncSig{"scalar": {Name: "scalar", Ret: Void}}}
			if _, err := Translate(file, options); err != nil {
				b.Fatal("benchmark must complete before timing", err)
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
