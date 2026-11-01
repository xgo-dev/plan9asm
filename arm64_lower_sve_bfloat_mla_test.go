package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEBFloatMLACompleteGo127Family(t *testing.T) {
	const source = `TEXT svebfloatmla(SB),$0-0
	ZBFMLA Z0.H, Z1.H, P0.M, Z2.H
	ZBFMLA Z0.H[0], Z3.H, Z4.H
	ZBFMLS Z5.H, Z6.H, P7.M, Z7.H
	ZBFMLS Z7.H[7], Z8.H, Z9.H
	ZBFMLALB Z10.H, Z11.H, Z12.S
	ZBFMLALB Z0.H[0], Z13.H, Z14.S
	ZBFMLALT Z15.H, Z16.H, Z17.S
	ZBFMLALT Z7.H[7], Z18.H, Z19.S
	ZBFMLSLB Z20.H, Z21.H, Z22.S
	ZBFMLSLB Z0.H[0], Z23.H, Z24.S
	ZBFMLSLT Z25.H, Z26.H, Z27.S
	ZBFMLSLT Z7.H[7], Z28.H, Z29.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svebfloatmla": {Name: "svebfloatmla", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+bf16,+sve,+sve-b16b16,+sve2p1"`,
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmla.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmla.lane.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmls.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fmls.lane.nxv8bf16",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlalb(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlalb.lane.v2(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlalt(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlalt.lane.v2(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlslb(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlslb.lane(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlslt(",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.bfmlslt.lane(",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s BF16 MLA lowering omitted actual call %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-bfloat-mla.ll", "arm64-sve-bfloat-mla.o", ll)
		})
	}
}

func TestTranslateARM64SVEBFloatMLAInfersIndependentFeatures(t *testing.T) {
	classes := []struct {
		name, instruction, features string
	}{
		{name: "non-widening", instruction: "ZBFMLA Z0.H, Z1.H, P0.M, Z2.H", features: "+sve,+sve-b16b16"},
		{name: "widening-add", instruction: "ZBFMLALB Z0.H, Z1.H, Z2.S", features: "+bf16,+sve"},
		{name: "widening-subtract", instruction: "ZBFMLSLB Z0.H, Z1.H, Z2.S", features: "+bf16,+sve,+sve2p1"},
	}
	for _, class := range classes {
		t.Run(class.name, func(t *testing.T) {
			source := "TEXT onebfloatmlafeature(SB),$0-0\n\t" + class.instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"onebfloatmlafeature": {Name: "onebfloatmlafeature", Ret: Void}}})
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
					compileLLVMToObject(t, llc, triple, "arm64-sve-bfloat-mla-feature.ll", "arm64-sve-bfloat-mla-feature.o", ll)
				})
			}
		})
	}
}

func TestTranslateARM64SVEBFloatMLARejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZBFMLA Z0.S, Z1.S, P0.M, Z2.S",
		"ZBFMLA Z0.H, Z1.H, P8.M, Z2.H",
		"ZBFMLS Z0.H, Z1.H, P0.Z, Z2.H",
		"ZBFMLA Z0.H, Z1.H, Z2.H",
		"ZBFMLA Z8.H[0], Z1.H, Z2.H",
		"ZBFMLS Z7.H[8], Z1.H, Z2.H",
		"ZBFMLALB Z0.H, Z1.H, Z2.H",
		"ZBFMLALT Z0.S, Z1.S, Z2.S",
		"ZBFMLSLB Z0.H, Z1.H, P0.M, Z2.S",
		"ZBFMLSLT.Z Z0.H, Z1.H, Z2.S",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvebfloatmla(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvebfloatmla": {Name: "badsvebfloatmla", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's BF16 MLA forms", instruction)
			}
		})
	}
}
