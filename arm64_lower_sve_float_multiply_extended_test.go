package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatMultiplyExtendedCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatmultiplyextendedforms(SB),$0-0\n")
	for index, width := range []string{"H", "S", "D"} {
		fmt.Fprintf(&source, "\tZFMULX Z1.%s, Z2.%s, P%d.M, Z2.%s\n", width, width, index, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatmultiplyextendedforms": {Name: "svefloatmultiplyextendedforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.fmulx.nxv8f16",
				"@llvm.aarch64.sve.fmulx.nxv4f32",
				"@llvm.aarch64.sve.fmulx.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating multiply-extended lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-multiply-extended.ll", "arm64-sve-float-multiply-extended.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatMultiplyExtendedRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFMULX Z1.B, Z2.B, P0.M, Z2.B",
		"ZFMULX Z1.H, Z2.S, P0.M, Z2.S",
		"ZFMULX Z1.S, Z2.S, P0, Z2.S",
		"ZFMULX Z1.S, Z2.S, P8.M, Z2.S",
		"ZFMULX Z1.S, Z2.S, P0.M, Z3.S",
		"ZFMULX Z1.S, Z2.S, Z3.S",
		"ZFMULX.Z Z1.S, Z2.S, P0.M, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatmultiplyextended(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatmultiplyextended": {Name: "badsvefloatmultiplyextended", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZFMULX forms", instruction)
			}
		})
	}
}
