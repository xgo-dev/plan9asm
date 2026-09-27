package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEBFloatArithmeticCompleteGo127Family(t *testing.T) {
	const source = `TEXT svebfloatarithmetic(SB),$0-0
	ZBFADD Z0.H, Z1.H, P0.M, Z1.H
	ZBFADD Z2.H, Z3.H, Z4.H
	ZBFSUB Z5.H, Z6.H, P7.M, Z6.H
	ZBFSUB Z7.H, Z8.H, Z9.H
	ZBFMUL Z10.H, Z11.H, P1.M, Z11.H
	ZBFMUL Z12.H, Z13.H, Z14.H
	ZBFMUL Z0.H[0], Z15.H, Z16.H
	ZBFMUL Z7.H[7], Z17.H, Z18.H
	ZBFMAX Z19.H, Z20.H, P2.M, Z20.H
	ZBFMAXNM Z21.H, Z22.H, P3.M, Z22.H
	ZBFMIN Z23.H, Z24.H, P4.M, Z24.H
	ZBFMINNM Z25.H, Z26.H, P5.M, Z26.H
	ZBFSCALE Z27.H, Z28.H, P6.M, Z28.H
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svebfloatarithmetic": {Name: "svebfloatarithmetic", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve-b16b16,+sve-bfscale"`,
				"= fadd <vscale x 8 x bfloat>",
				"= fsub <vscale x 8 x bfloat>",
				"= fmul <vscale x 8 x bfloat>",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fadd.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fsub.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmul.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmul.lane.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmax.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmaxnm.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmin.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fminnm.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fscale.nxv8bf16",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s BF16 arithmetic lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-bfloat-arithmetic.ll", "arm64-sve-bfloat-arithmetic.o", ll)
		})
	}
}

func TestTranslateARM64SVEBFloatArithmeticInfersIndependentFeatures(t *testing.T) {
	classes := []struct {
		name, instruction, features string
	}{
		{name: "b16b16", instruction: "ZBFADD Z0.H, Z1.H, Z2.H", features: "+sve,+sve-b16b16"},
		{name: "bfscale", instruction: "ZBFSCALE Z0.H, Z1.H, P0.M, Z1.H", features: "+sve,+sve-bfscale"},
	}
	for _, class := range classes {
		t.Run(class.name, func(t *testing.T) {
			source := "TEXT onebfloatfeature(SB),$0-0\n\t" + class.instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"onebfloatfeature": {Name: "onebfloatfeature", Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					want := `"target-features"="` + class.features + `"`
					if !strings.Contains(ll, want) {
						t.Fatalf("%s feature inference omitted %q for %s:\n%s", triple, want, class.instruction, ll)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-bfloat-feature.ll", "arm64-sve-bfloat-feature.o", ll)
				})
			}
		})
	}
}

func TestTranslateARM64SVEBFloatArithmeticRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZBFADD Z0.S, Z1.S, Z2.S",
		"ZBFADD Z0.H, Z1.H, P8.M, Z1.H",
		"ZBFSUB Z0.H, Z1.H, P0.M, Z2.H",
		"ZBFMUL Z0.H, Z1.H, P0.Z, Z1.H",
		"ZBFMUL Z8.H[0], Z1.H, Z2.H",
		"ZBFMUL Z7.H[8], Z1.H, Z2.H",
		"ZBFMAX Z0.H, Z1.H, Z2.H",
		"ZBFSCALE Z0.H, Z1.H, Z2.H",
		"ZBFMINNM.Z Z0.H, Z1.H, P0.M, Z1.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvebfloatarithmetic(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvebfloatarithmetic": {Name: "badsvebfloatarithmetic", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's BF16 arithmetic forms", instruction)
			}
		})
	}
}
