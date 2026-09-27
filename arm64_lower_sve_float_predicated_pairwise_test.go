package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatPredicatedPairwiseCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatpredicatedpairwise(SB),$0-0\n")
	for opIndex, op := range []string{"ZFABD", "ZFADDP", "ZFAMAX", "ZFAMIN"} {
		for widthIndex, width := range []string{"H", "S", "D"} {
			destination := opIndex*3 + widthIndex
			fmt.Fprintf(&source, "\t%s Z%d.%s, Z%d.%s, P%d.M, Z%d.%s\n", op, (destination+1)%32, width, destination, width, (opIndex+widthIndex)%8, destination, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatpredicatedpairwise": {Name: "svefloatpredicatedpairwise", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+faminmax,+sve,+sve2"`,
				"@llvm.aarch64.sve.fabd.nxv8f16",
				"@llvm.aarch64.sve.faddp.nxv4f32",
				"@llvm.aarch64.sve.famax.nxv2f64",
				"@llvm.aarch64.sve.famin.nxv8f16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE predicated floating pairwise lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-predicated-pairwise.ll", "arm64-sve-float-predicated-pairwise.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatPredicatedPairwiseRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFABD Z1.B, Z2.B, P0.M, Z2.B",
		"ZFADDP Z1.H, Z2.S, P0.M, Z2.S",
		"ZFAMAX Z1.S, Z2.S, P8.M, Z2.S",
		"ZFAMIN Z1.D, Z2.D, P0.Z, Z2.D",
		"ZFABD Z1.S, Z2.S, P0.M, Z3.S",
		"ZFADDP.Z Z1.D, Z2.D, P0.M, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatpredicatedpairwise(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatpredicatedpairwise": {Name: "badsvefloatpredicatedpairwise", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's predicated floating pairwise forms", instruction)
			}
		})
	}
}
