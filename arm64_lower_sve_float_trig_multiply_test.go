package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatTrigMultiplyCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloattrigmultiplyforms(SB),$0-0\n")
	for _, op := range []string{"ZFTSMUL", "ZFTSSEL"} {
		for _, width := range []string{"H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, Z3.%s\n", op, width, width, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloattrigmultiplyforms": {Name: "svefloattrigmultiplyforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.ftsmul.x.nxv8f16",
				"@llvm.aarch64.sve.ftsmul.x.nxv4f32",
				"@llvm.aarch64.sve.ftsmul.x.nxv2f64",
				"@llvm.aarch64.sve.ftssel.x.nxv8f16",
				"@llvm.aarch64.sve.ftssel.x.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating trigonometric multiply lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-trig-multiply.ll", "arm64-sve-float-trig-multiply.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatTrigMultiplyRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFTSMUL Z1.B, Z2.B, Z3.B",
		"ZFTSMUL Z1.H, Z2.S, Z3.S",
		"ZFTSMUL Z1.S, Z2.S, Z3.D",
		"ZFTSMUL Z1.S, Z2.S, P0.M, Z3.S",
		"ZFTSMUL.Z Z1.S, Z2.S, Z3.S",
		"ZFTSSEL Z1.B, Z2.B, Z3.B",
		"ZFTSSEL Z1.H, Z2.S, Z3.S",
		"ZFTSSEL.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloattrigmultiply(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloattrigmultiply": {Name: "badsvefloattrigmultiply", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ZFTSMUL forms", instruction)
			}
		})
	}
}
