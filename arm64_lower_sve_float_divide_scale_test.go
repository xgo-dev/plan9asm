package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatDivideScaleCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatdividescale(SB),$0-0\n")
	for index, width := range []string{"H", "S", "D"} {
		for opIndex, op := range []string{"ZFDIV", "ZFDIVR", "ZFSCALE"} {
			destination := index*3 + opIndex
			predicate := []int{0, 4, 7}[opIndex]
			fmt.Fprintf(&source, "\t%s Z%d.%s, Z%d.%s, P%d.M, Z%d.%s\n", op, destination+16, width, destination, width, predicate, destination, width)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatdividescale": {Name: "svefloatdividescale", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.fdiv.nxv8f16",
				"@llvm.aarch64.sve.fdiv.nxv4f32",
				"@llvm.aarch64.sve.fdiv.nxv2f64",
				"@llvm.aarch64.sve.fdivr.nxv8f16",
				"@llvm.aarch64.sve.fscale.nxv8f16",
				"@llvm.aarch64.sve.fscale.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating divide/scale lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-divide-scale.ll", "arm64-sve-float-divide-scale.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatDivideScaleRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFDIV Z1.B, Z2.B, P0.M, Z2.B",
		"ZFDIV Z1.S, Z2.S, P8.M, Z2.S",
		"ZFDIV Z1.S, Z2.S, P0.Z, Z2.S",
		"ZFDIV Z1.S, Z2.S, P0.M, Z3.S",
		"ZFDIVR Z1.H, Z2.S, P0.M, Z2.S",
		"ZFSCALE Z1.D, Z2.D, P0, Z2.D",
		"ZFSCALE.Z Z1.D, Z2.D, P0.M, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatdividescale(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatdividescale": {Name: "badsvefloatdividescale", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating divide/scale forms", instruction)
			}
		})
	}
}
