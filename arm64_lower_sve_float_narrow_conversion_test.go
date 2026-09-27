package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64SVEFloatNarrowConversionCompleteGo127Family(t *testing.T) {
	const source = `TEXT svefloatnarrowcvt(SB),$0-0
	ZBF1CVT Z0.B, Z1.H
	ZBF1CVTLT Z2.B, Z3.H
	ZBF2CVT Z4.B, Z5.H
	ZBF2CVTLT Z6.B, Z7.H
	ZF1CVT Z8.B, Z9.H
	ZF1CVTLT Z10.B, Z11.H
	ZF2CVT Z12.B, Z13.H
	ZF2CVTLT Z14.B, Z15.H
	ZBFCVT Z16.S, P0.M, Z17.H
	ZBFCVT Z18.S, P7.Z, Z19.H
	ZBFCVTNT Z20.S, P1.M, Z21.H
	ZBFCVTNT Z22.S, P6.Z, Z23.H
	ZBFCVTN [Z0.H-Z1.H], Z24.B
	ZFCVTNT Z2.S, P2.M, Z3.H
	ZFCVTNT Z4.S, P5.Z, Z5.H
	ZFCVTNT Z6.D, P3.M, Z7.S
	ZFCVTNT Z8.D, P4.Z, Z9.S
	ZFCVTN [Z10.H-Z11.H], Z25.B
	ZFCVTNB [Z12.S-Z13.S], Z26.B
	ZFCVTNT [Z30.S-Z31.S], Z27.B
	RET
`
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svefloatnarrowcvt": {Name: "svefloatnarrowcvt", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+bf16,+fp8,+sve,+sve2,+sve2p2"`,
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fp8.cvt1.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fp8.cvtlt1.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fp8.cvt2.nxv8bf16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fp8.cvtlt2.nxv8bf16",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fp8.cvt1.nxv8f16",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fp8.cvtlt1.nxv8f16",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fp8.cvt2.nxv8f16",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fp8.cvtlt2.nxv8f16",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvt.bf16f32.v2",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvtnt.bf16f32.v2",
				"= call <vscale x 8 x bfloat> @llvm.aarch64.sve.fcvtnt.z.bf16f32",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fcvtnt.f16f32",
				"= call <vscale x 8 x half> @llvm.aarch64.sve.fcvtnt.z.f16f32",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.fcvtnt.f32f64",
				"= call <vscale x 4 x float> @llvm.aarch64.sve.fcvtnt.z.f32f64",
				"= call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtn.nxv8bf16",
				"= call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtn.nxv8f16",
				"= call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtnb.nxv4f32",
				"= call <vscale x 16 x i8> @llvm.aarch64.sve.fp8.cvtnt.nxv4f32",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s floating narrowing conversion lowering omitted actual call %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-float-narrow-conversion.ll", "arm64-sve-float-narrow-conversion.o", ll)
		})
	}
}

func TestTranslateARM64SVEFloatNarrowConversionRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZBF1CVT Z0.H, Z1.H",
		"ZBF1CVTLT Z0.B, Z1.S",
		"ZF2CVT Z0.B, Z1.D",
		"ZBFCVT Z0.S, P8.M, Z1.H",
		"ZBFCVTNT Z0.D, P0.M, Z1.S",
		"ZFCVTNT Z0.H, P0.Z, Z1.B",
		"ZBFCVTN [Z1.H-Z2.H], Z3.B",
		"ZFCVTN [Z2.H, Z3.H], Z4.B",
		"ZFCVTNB [Z2.H-Z3.H], Z4.B",
		"ZFCVTNT [Z2.S-Z3.S], Z4.H",
		"ZF1CVT.Z Z0.B, Z1.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvefloatnarrowcvt(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvefloatnarrowcvt": {Name: "badsvefloatnarrowcvt", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's floating narrowing conversion forms", instruction)
			}
		})
	}
}

func TestTranslateARM64SVEFloatNarrowConversionInfersEachFeatureClass(t *testing.T) {
	classes := []struct {
		name     string
		source   string
		features string
	}{
		{name: "fp8-to-bf16", source: "ZBF1CVT Z0.B, Z1.H", features: "+fp8,+sve,+sve2,+sve2p2"},
		{name: "bf16-predicated", source: "ZBFCVTNT Z0.S, P0.M, Z1.H", features: "+bf16,+sve"},
		{name: "sve2-merging-top-narrow", source: "ZFCVTNT Z0.D, P0.M, Z1.S", features: "+sve,+sve2"},
		{name: "sve2p2-zeroing-top-narrow", source: "ZFCVTNT Z0.D, P0.Z, Z1.S", features: "+sve,+sve2,+sve2p2"},
		{name: "bf16-to-fp8", source: "ZBFCVTN [Z0.H-Z1.H], Z2.B", features: "+fp8,+sve,+sve2,+sve2p2"},
	}
	for _, class := range classes {
		t.Run(class.name, func(t *testing.T) {
			source := "TEXT onefeatureclass(SB),$0-0\n\t" + class.source + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"onefeatureclass": {Name: "onefeatureclass", Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					want := `"target-features"="` + class.features + `"`
					if !strings.Contains(ll, want) {
						t.Fatalf("%s feature inference omitted %q for %s:\n%s", triple, want, class.source, ll)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-float-narrow-feature.ll", "arm64-sve-float-narrow-feature.o", ll)
				})
			}
		})
	}
}
