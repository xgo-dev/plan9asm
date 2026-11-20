package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatMultiplyAddendCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatmultiplyaddendforms(SB),$0-0\n")
	for _, op := range []string{"ZFMAD", "ZFMSB", "ZFNMAD", "ZFNMSB"} {
		for index, width := range []string{"H", "S", "D"} {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, P%d.M, Z3.%s\n", op, width, width, index, width)
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatmultiplyaddendforms": {Name: "svefloatmultiplyaddendforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.fmad.nxv8f16",
				"@llvm.aarch64.sve.fmsb.nxv4f32",
				"@llvm.aarch64.sve.fnmad.nxv2f64",
				"@llvm.aarch64.sve.fnmsb.nxv8f16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating multiply-addend lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-multiply-addend.ll", "arm64-sve-float-multiply-addend.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatMultiplyAddendRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFMAD Z1.B, Z2.B, P0.M, Z3.B",
		"ZFMSB Z1.H, Z2.S, P0.M, Z3.S",
		"ZFNMAD Z1.H, Z2.H, P0, Z3.H",
		"ZFNMSB Z1.S, Z2.S, P8.M, Z3.S",
		"ZFMAD Z7.H[0], Z2.H, Z3.H",
		"ZFMSB.Z Z1.S, Z2.S, P0.M, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatmultiplyaddend(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatmultiplyaddend": {Name: "badsvefloatmultiplyaddend", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating multiply-addend forms", instruction)
			}
		})
	}
}
