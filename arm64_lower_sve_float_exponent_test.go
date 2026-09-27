package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatExponentCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatexponent(SB),$0-0\n")
	for index, width := range []string{"H", "S", "D"} {
		fmt.Fprintf(&source, "\tZFEXPA Z%d.%s, Z%d.%s\n", index, width, index+4, width)
		fmt.Fprintf(&source, "\tZFLOGB Z%d.%s, P%d.M, Z%d.%s\n", index+8, width, index, index+12, width)
		fmt.Fprintf(&source, "\tZFLOGB Z%d.%s, P%d.Z, Z%d.%s\n", index+16, width, index+3, index+20, width)
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatexponent": {Name: "svefloatexponent", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.fexpa.x.nxv8f16",
				"@llvm.aarch64.sve.fexpa.x.nxv4f32",
				"@llvm.aarch64.sve.fexpa.x.nxv2f64",
				"@llvm.aarch64.sve.flogb.nxv8f16",
				"@llvm.aarch64.sve.flogb.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating exponent lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-exponent.ll", "arm64-sve-float-exponent.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatExponentRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFEXPA Z1.B, Z2.B",
		"ZFEXPA Z1.S, Z2.D",
		"ZFLOGB Z1.B, P0.M, Z2.B",
		"ZFLOGB Z1.S, P8.M, Z2.S",
		"ZFLOGB Z1.S, P0, Z2.S",
		"ZFLOGB Z1.S, P0.Z, Z2.D",
		"ZFEXPA.Z Z1.D, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatexponent(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatexponent": {Name: "badsvefloatexponent", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating exponent forms", instruction)
			}
		})
	}
}
