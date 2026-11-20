package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatMultiplyCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatmultiplyforms(SB),$0-0\n")
	for index, width := range []string{"H", "S", "D"} {
		maximumVector := []int{7, 7, 15}[index]
		maximumLane := []int{7, 3, 1}[index]
		fmt.Fprintf(&source, "\tZFMUL Z1.%s, Z2.%s, P%d.M, Z2.%s\n", width, width, index, width)
		fmt.Fprintf(&source, "\tZFMUL Z3.%s, Z4.%s, Z5.%s\n", width, width, width)
		fmt.Fprintf(&source, "\tZFMUL Z%d.%s[%d], Z6.%s, Z7.%s\n", maximumVector, width, maximumLane, width, width)
		for _, immediate := range []string{"0.5", "2.0"} {
			fmt.Fprintf(&source, "\tZFMUL $(%s), Z8.%s, P%d.M, Z8.%s\n", immediate, width, index, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatmultiplyforms": {Name: "svefloatmultiplyforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				" fmul <vscale x ",
				"@llvm.aarch64.sve.fmul.lane.nxv8f16",
				"@llvm.aarch64.sve.fmul.lane.nxv4f32",
				"@llvm.aarch64.sve.fmul.lane.nxv2f64",
				" select <vscale x ",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating multiply lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-multiply.ll", "arm64-sve-float-multiply.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatMultiplyRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFMUL Z1.B, Z2.B, Z3.B",
		"ZFMUL Z1.H, Z2.S, Z3.S",
		"ZFMUL Z8.H[0], Z2.H, Z3.H",
		"ZFMUL Z7.H[8], Z2.H, Z3.H",
		"ZFMUL $(1.0), Z1.S, P0.M, Z1.S",
		"ZFMUL Z1.S, Z2.S, P0, Z2.S",
		"ZFMUL Z1.S, Z2.S, P8.M, Z2.S",
		"ZFMUL Z1.S, Z2.S, P0.M, Z3.S",
		"ZFMUL.Z Z1.S, Z2.S, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatmultiply(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatmultiply": {Name: "badsvefloatmultiply", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating multiply forms", instruction)
			}
		})
	}
}
