package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedDoubleToSingleCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses four related tables for this family:
	//   CVTPD2PS:  X/m128 -> X
	//   VCVTPD2PSX: X/m128 -> X
	//   VCVTPD2PSY: Y/m256 -> X
	//   VCVTPD2PS:  Z/m512 -> Y
	// The EVEX forms accept scalar-double broadcast and K1-K7 masking. Only
	// the 512-bit source form accepts explicit rounding.
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
			// Go permits EVEX X/Y registers through 31 in 386 mode, while a
			// Z source (the Yzm class) remains limited to Z0-Z7 there.
			lastZ := 21
			if target.goarch == "386" {
				lastZ = 7
			}
			var src strings.Builder
			src.WriteString("TEXT packeddoubletosingleforms(SB),NOSPLIT,$0-0\n")
			src.WriteString("\tCVTPD2PS X0, X1\n")
			src.WriteString("\tCVTPD2PS 8(AX), X2\n")
			src.WriteString("\tVCVTPD2PSX X20, X0\n")
			src.WriteString("\tVCVTPD2PSX (AX), X1\n")
			src.WriteString("\tVCVTPD2PSX X20, K1, X21\n")
			src.WriteString("\tVCVTPD2PSX.Z 16(AX), K2, X3\n")
			src.WriteString("\tVCVTPD2PSX.BCST 24(AX), X4\n")
			src.WriteString("\tVCVTPD2PSX.BCST.Z 32(AX), K3, X5\n")
			src.WriteString("\tVCVTPD2PSY Y20, X0\n")
			src.WriteString("\tVCVTPD2PSY (AX), X1\n")
			src.WriteString("\tVCVTPD2PSY Y20, K4, X21\n")
			src.WriteString("\tVCVTPD2PSY.Z 40(AX), K5, X3\n")
			src.WriteString("\tVCVTPD2PSY.BCST 48(AX), X4\n")
			src.WriteString("\tVCVTPD2PSY.BCST.Z 56(AX), K6, X5\n")
			fmt.Fprintf(&src, "\tVCVTPD2PS Z%d, Y0\n", lastZ)
			src.WriteString("\tVCVTPD2PS (AX), Y1\n")
			fmt.Fprintf(&src, "\tVCVTPD2PS Z%d, K1, Y21\n", lastZ)
			src.WriteString("\tVCVTPD2PS.Z 64(AX), K2, Y3\n")
			src.WriteString("\tVCVTPD2PS.BCST 72(AX), Y4\n")
			src.WriteString("\tVCVTPD2PS.BCST.Z 80(AX), K3, Y5\n")
			for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				fmt.Fprintf(&src, "\tVCVTPD2PS.%s Z%d, Y6\n", rounding, lastZ)
			}
			fmt.Fprintf(&src, "\tVCVTPD2PS.RN_SAE.Z Z%d, K7, Y6\n", lastZ)
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packeddoubletosingleforms": {Name: "packeddoubletosingleforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-double-to-single-"+target.name+".ll", "packed-double-to-single-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedDoubleToSingleRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"CVTPD2PS X0",
		"CVTPD2PS Y0, X1",
		"CVTPD2PS X0, (AX)",
		"CVTPD2PS.Z X0, X1",
		"VCVTPD2PSX Y0, X1",
		"VCVTPD2PSX X0, Y1",
		"VCVTPD2PSY X0, X1",
		"VCVTPD2PSY Y0, Y1",
		"VCVTPD2PS Z0, X1",
		"VCVTPD2PS Y0, Y1",
		"VCVTPD2PS Z0, Z1",
		"VCVTPD2PSX X0, K0, X1",
		"VCVTPD2PSY.Z Y0, X1",
		"VCVTPD2PS.Z Z0, Y1",
		"VCVTPD2PSX.BCST X0, X1",
		"VCVTPD2PSY.BCST Y0, X1",
		"VCVTPD2PS.BCST Z0, Y1",
		"VCVTPD2PSX.RN_SAE X0, X1",
		"VCVTPD2PSY.RD_SAE Y0, X1",
		"VCVTPD2PS.RU_SAE (AX), Y1",
		"VCVTPD2PS.SAE Z0, Y1",
		"VCVTPD2PS.BCST.RN_SAE (AX), Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedDoubleToSingleRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}

	for _, instruction := range []string{
		"CVTPD2PS X8, X0",
		"CVTPD2PS X0, X8",
		"VCVTPD2PS Z8, Y0",
		"VCVTPD2PS Z20, K1, Y0",
	} {
		assertX86PackedDoubleToSingleRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86PackedDoubleToSingleRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed double-to-single forms", instruction)
	}
}
