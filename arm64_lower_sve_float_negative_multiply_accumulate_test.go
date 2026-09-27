package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatNegativeMultiplyAccumulateCompleteGo127Family(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svefloatnegativemultiplyaccumulateforms(SB),$0-0\n")
	for _, op := range []string{"ZFNMLA", "ZFNMLS"} {
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatnegativemultiplyaccumulateforms": {Name: "svefloatnegativemultiplyaccumulateforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"\"target-features\"=\"+sve\"",
				"@llvm.aarch64.sve.fnmla.nxv8f16",
				"@llvm.aarch64.sve.fnmla.nxv4f32",
				"@llvm.aarch64.sve.fnmls.nxv2f64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE floating negative multiply-accumulate lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-negative-multiply-accumulate.ll", "arm64-sve-float-negative-multiply-accumulate.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatNegativeMultiplyAccumulateRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZFNMLA Z1.B, Z2.B, P0.M, Z3.B",
		"ZFNMLS Z1.H, Z2.S, P0.M, Z3.S",
		"ZFNMLA Z1.H, Z2.H, P0, Z3.H",
		"ZFNMLS Z1.S, Z2.S, P8.M, Z3.S",
		"ZFNMLA Z7.H[0], Z2.H, Z3.H",
		"ZFNMLS.Z Z1.S, Z2.S, P0.M, Z3.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatnegativemultiplyaccumulate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatnegativemultiplyaccumulate": {Name: "badsvefloatnegativemultiplyaccumulate", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE floating negative multiply-accumulate forms", instruction)
			}
		})
	}
}
