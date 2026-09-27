package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86InLaneFloatingPermuteCompleteGoAssemblerForms(t *testing.T) {
	// VPERMILPD and VPERMILPS share Go 1.27's 18-row _yvpermilpd table:
	// immediate and variable-control VEX X/Y forms, EVEX X/Y/Z forms,
	// scalar-memory broadcast, and K1-K7 merge/zero masking.
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
			src.WriteString("TEXT inlanefloatingpermuteforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VPERMILPD", "VPERMILPS"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&src, "\t%s $-128, %s0, %s1\n", op, width, width)
					fmt.Fprintf(&src, "\t%s $255, (AX), %s2\n", op, width)
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s (AX), %s20, %s21\n", op, width, width)
					fmt.Fprintf(&src, "\t%s $7, %s20, %s21\n", op, width, width)
				}
				fmt.Fprintf(&src, "\t%s $255, Z0, Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s Z0, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s.BCST $7, (AX), Z%d\n", op, zLast)
				fmt.Fprintf(&src, "\t%s.BCST (AX), Z6, Z%d\n", op, zLast)
				if target.goarch == "amd64" {
					for _, width := range []string{"X", "Y", "Z"} {
						fmt.Fprintf(&src, "\t%s $7, %s20, K1, %s21\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.Z $7, (AX), K2, %s22\n", op, width)
						fmt.Fprintf(&src, "\t%s %s20, %s21, K3, %s22\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z (AX), %s21, K4, %s22\n", op, width, width)
					}
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
					"inlanefloatingpermuteforms": {Name: "inlanefloatingpermuteforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "in-lane-floating-permute-"+target.name+".ll", "in-lane-floating-permute-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86InLaneFloatingPermuteRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPERMILPS $-129, X0, X1",
		"VPERMILPD $256, X0, X1",
		"VPERMILPS $-1, X20, X21",
		"VPERMILPD $-1, Z0, Z1",
		"VPERMILPS X0, X1",
		"VPERMILPD X0, Y1, Y2",
		"VPERMILPS X0, X1, (AX)",
		"VPERMILPD.BCST X0, X1, X2",
		"VPERMILPS.BCST $7, X0, X1",
		"VPERMILPD.Z $7, X0, X1",
		"VPERMILPS X0, X1, K0, X2",
		"VPERMILPD.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86InLaneFloatingPermuteRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}

	for _, instruction := range []string{
		"VPERMILPS $7, Z8, Z0",
		"VPERMILPD Z0, Z1, Z8",
		"VPERMILPS $-1, X20, X21",
		"VPERMILPD X0, X1, K1, X2",
		"VPERMILPS.Z $7, X0, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86InLaneFloatingPermuteRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86InLaneFloatingPermuteRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's _yvpermilpd forms for %s", instruction, goarch)
	}
}
