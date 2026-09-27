package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedHalfConversionCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 defines the whole F16C/AVX-512 FP16 conversion pair in
	// _yvcvtph2ps and _yvcvtps2ph:
	//
	//   VCVTPH2PS X/m -> X or Y; Y/m -> Z
	//   VCVTPS2PH imm8, X -> X/m; Y -> X/m; Z -> Y/m
	//
	// EVEX forms additionally accept K1-K7 and register-destination zeroing.
	// The VEX VCVTPS2PH rows accept both signed and unsigned imm8 spellings.
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString(`TEXT halfconversionforms(SB),NOSPLIT,$0-0
	VCVTPH2PS X0, X1
	VCVTPH2PS 8(AX), X2
	VCVTPH2PS X20, X21
	VCVTPH2PS X3, K1, X4
	VCVTPH2PS.Z 16(AX), K2, X5
	VCVTPH2PS X6, Y7
	VCVTPH2PS 32(AX), Y8
	VCVTPH2PS X20, K3, Y21
	VCVTPH2PS.Z 48(AX), K4, Y9
	VCVTPH2PS Y10, Z1
	VCVTPH2PS 64(AX), Z2
	VCVTPH2PS Y20, K5, Z3
	VCVTPH2PS.Z 96(AX), K6, Z4
	VCVTPH2PS.SAE Y10, Z5
	VCVTPH2PS.SAE.Z Y11, K7, Z6
	VCVTPS2PH $0, X0, X1
	VCVTPS2PH $-1, X2, 128(AX)
	VCVTPS2PH $255, Y3, X4
	VCVTPS2PH $-128, Y5, 160(AX)
	VCVTPS2PH $7, Z1, Y2
	VCVTPS2PH.SAE $8, Z3, Y4
`)
			// Go 1.27's 386 assembler accepts the EVEX VCVTPH2PS mask
			// rows, but its operand parser does not expose the four-operand
			// masked VCVTPS2PH rows. Keep this difference visible here.
			if target.goarch == "amd64" {
				source.WriteString(`	VCVTPS2PH $126, X7, K5, X17
	VCVTPS2PH.Z $126, X7, K5, X17
	VCVTPS2PH $126, X7, K5, 192(AX)
	VCVTPS2PH $94, Y1, K7, X15
	VCVTPS2PH.Z $94, Y1, K7, X15
	VCVTPS2PH $94, Y1, K7, 224(AX)
	VCVTPS2PH $121, Z5, K7, Y28
	VCVTPS2PH.SAE.Z $13, Z2, K6, Y13
	VCVTPS2PH $121, Z5, K7, 256(AX)
`)
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"halfconversionforms": {Name: "halfconversionforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fpext <", "half>", "fptrunc <"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("half conversion IR is missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-half-conversion-"+target.name+".ll", "packed-half-conversion-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedHalfConversionRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VCVTPH2PS X0",
		"VCVTPH2PS X0, X1, X2",
		"VCVTPH2PS Y0, X1",
		"VCVTPH2PS X0, Z1",
		"VCVTPH2PS X0, K0, X1",
		"VCVTPH2PS.Z X0, X1",
		"VCVTPH2PS.BCST (AX), X1",
		"VCVTPS2PH X0, X1",
		"VCVTPS2PH $256, X0, X1",
		"VCVTPS2PH $0, Z0, X1",
		"VCVTPS2PH $0, X0, Y1",
		"VCVTPS2PH $0, X0, K0, X1",
		"VCVTPS2PH.Z $0, X0, X1",
		"VCVTPS2PH.Z $0, X0, K1, (AX)",
		"VCVTPS2PH.BCST $0, X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedHalfConversionRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VCVTPS2PH $-1, X20, X21",
		"VCVTPS2PH $-1, Y20, X21",
		"VCVTPS2PH $0, X0, K1, X1",
		"VCVTPS2PH $0, Y0, K1, X1",
		"VCVTPS2PH $0, Z0, K1, Y1",
	} {
		assertX86PackedHalfConversionRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86PackedHalfConversionRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT bad(SB),NOSPLIT,$0-0\n\t%s\n\tRET\n", instruction))
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's VCVTPH2PS/VCVTPS2PH tables", instruction)
	}
}
