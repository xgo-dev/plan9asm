package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatComplexAddCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatcomplexadd(SB),$0-0\n")
	for widthIndex, width := range []string{"H", "S", "D"} {
		for rotationIndex, rotation := range []int{90, 270} {
			destination := widthIndex*2 + rotationIndex
			fmt.Fprintf(&source, "\tZFCADD $%d, Z%d.%s, Z%d.%s, P%d.M, Z%d.%s\n", rotation, destination+16, width, destination, width, destination+2, destination, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatcomplexadd": {Name: "svefloatcomplexadd", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.fcadd.nxv8f16",
				"@llvm.aarch64.sve.fcadd.nxv4f32",
				"@llvm.aarch64.sve.fcadd.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating complex-add lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-complex-add.ll", "arm64-sve-float-complex-add.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatComplexAddRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFCADD $0, Z1.H, Z2.H, P0.M, Z2.H",
		"ZFCADD $180, Z1.S, Z2.S, P0.M, Z2.S",
		"ZFCADD $90, Z1.B, Z2.B, P0.M, Z2.B",
		"ZFCADD $90, Z1.S, Z2.D, P0.M, Z2.D",
		"ZFCADD $270, Z1.D, Z2.D, P8.M, Z2.D",
		"ZFCADD $270, Z1.D, Z2.D, P0.Z, Z2.D",
		"ZFCADD $270, Z1.D, Z2.D, P0.M, Z3.D",
		"ZFCADD.Z $270, Z1.D, Z2.D, P0.M, Z2.D",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatcomplexadd(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatcomplexadd": {Name: "badsvefloatcomplexadd", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating complex-add forms", instruction)
			}
		})
	}
}
