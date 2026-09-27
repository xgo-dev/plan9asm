package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86Reciprocal14CompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's _yvexpandpd table accepts EVEX X/Y/Z register or memory
	// sources, optional scalar-memory broadcast, and optional K1-K7 merge/.Z
	// masking. _yvgetexpsd accepts scalar memory/X sources, an X passthrough,
	// and the same optional mask. The 386 frontend accepts the unmasked EVEX
	// forms but not mask operands, and limits Z registers to Z0-Z7.
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
			lastZ := 31
			if target.goarch == "386" {
				lastZ = 7
			}
			var source strings.Builder
			source.WriteString("TEXT reciprocal14forms(SB),$0-0\n")
			for _, op := range []string{"VRCP14PS", "VRCP14PD", "VRSQRT14PS", "VRSQRT14PD"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s1, %s20\n", op, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20\n", op, width)
					fmt.Fprintf(&source, "\t%s.BCST 16(AX), %s20\n", op, width)
				}
				fmt.Fprintf(&source, "\t%s Z1, Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s 24(AX), Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s.BCST 32(AX), Z%d\n", op, lastZ)
				fmt.Fprintf(&source, "\t%s X1, K1, X20\n", op)
				fmt.Fprintf(&source, "\t%s.Z 40(AX), K2, Y20\n", op)
				fmt.Fprintf(&source, "\t%s.BCST.Z 48(AX), K3, Z%d\n", op, lastZ)
			}
			for _, op := range []string{"VRCP14SS", "VRCP14SD", "VRSQRT14SS", "VRSQRT14SD"} {
				fmt.Fprintf(&source, "\t%s X1, X20, X21\n", op)
				fmt.Fprintf(&source, "\t%s 56(AX), X20, X21\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X20, K4, X21\n", op)
					fmt.Fprintf(&source, "\t%s.Z 64(AX), X20, K5, X21\n", op)
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"reciprocal14forms": {Name: "reciprocal14forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{
				"@llvm.x86.avx512.rcp14.ps.128", "@llvm.x86.avx512.rcp14.ps.256", "@llvm.x86.avx512.rcp14.ps.512",
				"@llvm.x86.avx512.rcp14.pd.128", "@llvm.x86.avx512.rcp14.pd.256", "@llvm.x86.avx512.rcp14.pd.512",
				"@llvm.x86.avx512.rsqrt14.ps.128", "@llvm.x86.avx512.rsqrt14.ps.256", "@llvm.x86.avx512.rsqrt14.ps.512",
				"@llvm.x86.avx512.rsqrt14.pd.128", "@llvm.x86.avx512.rsqrt14.pd.256", "@llvm.x86.avx512.rsqrt14.pd.512",
				"@llvm.x86.avx512.rcp14.ss", "@llvm.x86.avx512.rcp14.sd",
				"@llvm.x86.avx512.rsqrt14.ss", "@llvm.x86.avx512.rsqrt14.sd",
			} {
				if !strings.Contains(ll, intrinsic) {
					t.Fatalf("translation omitted %s:\n%s", intrinsic, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "reciprocal14-"+target.name+".ll", "reciprocal14-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86Reciprocal14RejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VRCP14PS X0, Y1"},
		{goarch: "amd64", instruction: "VRSQRT14PD.Z Z0, Z1"},
		{goarch: "amd64", instruction: "VRCP14PS.BCST X0, X1"},
		{goarch: "amd64", instruction: "VRCP14PD.SAE Z0, Z1"},
		{goarch: "amd64", instruction: "VRSQRT14PS Z0, K0, Z1"},
		{goarch: "amd64", instruction: "VRCP14SS X0, X1"},
		{goarch: "amd64", instruction: "VRCP14SD Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRSQRT14SS.BCST 8(AX), X1, X2"},
		{goarch: "amd64", instruction: "VRSQRT14SD.SAE X0, X1, X2"},
		{goarch: "amd64", instruction: "VRCP14SS.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VRCP14SS X0, X1, K0, X2"},
		{goarch: "386", instruction: "VRCP14SS X0, X1, K1, X2"},
		{goarch: "386", instruction: "VRSQRT14PD Z0, Z8"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's reciprocal14 tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
