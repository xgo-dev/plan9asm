package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86SameWidthPackedConversionCompleteGoAssemblerForms(t *testing.T) {
	// These five opcodes share Go 1.27's _yvcvtdq2ps table. All accept X/Y/Z
	// register or memory sources, scalar-memory broadcast, and K1-K7 masks.
	// The Z forms of all but VCVTTPS2DQ accept explicit rounding; the
	// truncating conversion accepts SAE instead.
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
			zLast := 21
			if target.goarch == "386" {
				zLast = 7
			}
			var src strings.Builder
			src.WriteString("TEXT samewidthpackedconversionforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VCVTDQ2PS", "VCVTPS2DQ", "VCVTTPS2DQ", "VSQRTPD", "VSQRTPS"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
					fmt.Fprintf(&src, "\t%s (AX), %s2\n", op, width)
					fmt.Fprintf(&src, "\t%s %s20, %s21\n", op, width, width)
					fmt.Fprintf(&src, "\t%s %s20, K1, %s21\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.Z (AX), K2, %s22\n", op, width)
					fmt.Fprintf(&src, "\t%s.BCST 8(AX), %s22\n", op, width)
					fmt.Fprintf(&src, "\t%s.BCST.Z 8(AX), K3, %s23\n", op, width)
				}
				fmt.Fprintf(&src, "\t%s Z0, Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s (AX), Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s Z6, K4, Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s.Z (AX), K5, Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s.BCST 8(AX), Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s.BCST.Z 8(AX), K6, Z%d\n", op, zLast)
				if op == "VCVTTPS2DQ" {
					fmt.Fprintf(&src, "\t%s.SAE Z6, Z%d\n", op, zLast)
					fmt.Fprintf(&src, "\t%s.SAE.Z Z6, K7, Z%d\n", op, zLast)
				} else {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&src, "\t%s.%s Z6, Z%d\n", op, rounding, zLast)
					}
					fmt.Fprintf(&src, "\t%s.RN_SAE.Z Z6, K7, Z%d\n", op, zLast)
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"samewidthpackedconversionforms": {Name: "samewidthpackedconversionforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "same-width-packed-conversion-"+target.name+".ll", "same-width-packed-conversion-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86SameWidthPackedConversionRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VCVTDQ2PS X0",
		"VCVTPS2DQ X0, Y1",
		"VCVTTPS2DQ X0, (AX)",
		"VSQRTPD X0, K0, X1",
		"VSQRTPS.Z X0, X1",
		"VCVTDQ2PS.BCST X0, X1",
		"VCVTPS2DQ.SAE Z0, Z1",
		"VCVTTPS2DQ.RN_SAE Z0, Z1",
		"VSQRTPD.RN_SAE X0, X1",
		"VSQRTPS.RN_SAE (AX), Z1",
		"VCVTDQ2PS.BCST.RN_SAE (AX), Z1",
		"VCVTTPS2DQ.BCST.SAE (AX), Z1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86SameWidthPackedConversionRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}

	for _, instruction := range []string{
		"VCVTDQ2PS Z8, Z0",
		"VCVTPS2DQ Z0, Z8",
		"VCVTTPS2DQ.SAE Z8, Z0",
		"VSQRTPD.RN_SAE Z0, Z8",
		"VSQRTPS Z0, K1, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86SameWidthPackedConversionRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86SameWidthPackedConversionRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's _yvcvtdq2ps forms for %s", instruction, goarch)
	}
}
