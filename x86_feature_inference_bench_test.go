package plan9asm

import (
	"strings"
	"testing"
)

// Parsing is excluded. These fixed functions isolate family recognition and
// feature aggregation; they do not measure lowering or LLVM compilation.
func BenchmarkX86FeatureInference(b *testing.B) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"MOVL AX,BX",
			"VPXOR X0,X1,X2",
			"VMOVUPS Y0,Y1",
			"PADDL X0,X1",
			"PSHUFB X0,X1",
			"VCVTSD2SS X0,X1,X2",
			"ADDL AX,BX",
			"LEAL 8(AX)(BX*2),CX",
			"JEQ feature_done",
		} {
			b.Run(arch+"/"+row, func(b *testing.B) {
				tail := "RET\n"
				if row == "JEQ feature_done" {
					tail = "feature_done:\n" + tail
				}
				file, err := Parse(ArchAMD64, "TEXT feature(SB),4,$0-0\n"+
					strings.Repeat(row+"\n", 64)+tail)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					x86FeatureInferenceBenchmarkSink = inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, file.Funcs[0])
				}
			})
		}
	}
}

var x86FeatureInferenceBenchmarkSink string

// Include analysis, lowering and LLVM verification for one initialized GP
// function. This is separate from the inference-only benchmark above.
func BenchmarkX86BaselineGPTranslation(b *testing.B) {
	source := "TEXT feature(SB),4,$0-0\nMOVL $1,AX\nMOVL $3,BX\n" +
		strings.Repeat("ADDL AX,BX\nLEAL 8(AX)(BX*2),CX\nJEQ feature_done\n", 64) +
		"feature_done:\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		b.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"feature": {Name: "feature", Ret: Void}}}
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
}
