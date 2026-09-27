package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedTestMaskCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 gives VPTESTM{B,W,D,Q} and VPTESTNM{B,W,D,Q} the same
	// _yvpshufbitqmb operand table: X/Y/Z r/m first source, a matching
	// vector second source, an optional K1-K7 write mask, and a K
	// destination. D/Q additionally enable scalar-memory broadcast.
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
			source.WriteString("TEXT packedtestmaskforms(SB),$0-0\n")
			for _, op := range []string{
				"VPTESTMB", "VPTESTMW", "VPTESTMD", "VPTESTMQ",
				"VPTESTNMB", "VPTESTNMW", "VPTESTNMD", "VPTESTNMQ",
			} {
				zLast := 31
				if target.goarch == "386" {
					zLast = 7
				}
				fmt.Fprintf(&source, "\t%s X1, X31, K0\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), X31, K2\n", op)
				fmt.Fprintf(&source, "\t%s Y1, Y31, K3\n", op)
				fmt.Fprintf(&source, "\t%s 40(AX), Y31, K5\n", op)
				fmt.Fprintf(&source, "\t%s Z1, Z%d, K6\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 104(AX), Z%d, K0\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 0, Z%d, K0\n", op, zLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s 112(AX), X31, K1, K2\n", op)
					fmt.Fprintf(&source, "\t%s 120(AX), Y31, K4, K5\n", op)
					fmt.Fprintf(&source, "\t%s 128(AX), Z31, K7, K0\n", op)
				}
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					fmt.Fprintf(&source, "\t%s.BCST 168(AX), X31, K1\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 176(AX), Y31, K3\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 184(AX), Z%d, K4\n", op, zLast)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.BCST 192(AX), Y31, K2, K3\n", op)
					}
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
					"packedtestmaskforms": {Name: "packedtestmaskforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"icmp ne", "icmp eq", "store i64"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("translation omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-test-mask-"+target.name+".ll", "packed-test-mask-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedTestMaskRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPTESTMD X0, X1"},
		{goarch: "amd64", instruction: "VPTESTMD X0, Y1, K1"},
		{goarch: "amd64", instruction: "VPTESTMD X0, (AX), K1"},
		{goarch: "amd64", instruction: "VPTESTMD X0, X1, K0, K1"},
		{goarch: "amd64", instruction: "VPTESTMD X0, X1, AX"},
		{goarch: "amd64", instruction: "VPTESTMD.Z X0, X1, K1"},
		{goarch: "amd64", instruction: "VPTESTMB.BCST (AX), X1, K1"},
		{goarch: "amd64", instruction: "VPTESTMW.BCST (AX), X1, K1"},
		{goarch: "amd64", instruction: "VPTESTMD.BCST X0, X1, K1"},
		{goarch: "amd64", instruction: "VPTESTNMQ X32, X1, K1"},
		{goarch: "386", instruction: "VPTESTMD X1, X2, K1, K2"},
		{goarch: "386", instruction: "VPTESTMD Z8, Z0, K1"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's packed test-mask forms for %s", test.instruction, test.goarch)
			}
		})
	}
}
