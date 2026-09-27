package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedUnsignedAverageCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast, zLast := 15, 22
			if target.goarch == "386" {
				legacyLast, zLast = 7, 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedunsignedaverageforms(SB),NOSPLIT,$0-0\n")
			for _, stem := range []string{"PAVGB", "PAVGW"} {
				fmt.Fprintf(&source, "\t%s M0, M1\n", stem)
				fmt.Fprintf(&source, "\t%s 8(AX), M2\n", stem)
				fmt.Fprintf(&source, "\t%s X0, X%d\n", stem, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", stem, legacyLast)
				vector := "V" + stem
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", vector, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20, %s21\n", vector, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, %s22\n", vector, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z 8(AX), %s21, K7, %s22\n", vector, width, width)
					}
				}
				fmt.Fprintf(&source, "\t%s Z0, Z6, Z%d\n", vector, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, Z%d\n", vector, zLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s Z20, Z21, K2, Z22\n", vector)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), Z21, K6, Z22\n", vector)
				}
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
					"packedunsignedaverageforms": {Name: "packedunsignedaverageforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-unsigned-average-"+target.name+".ll", "packed-unsigned-average-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedUnsignedAverageRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PAVGB.Z X0, X1",
		"PAVGW X0",
		"PAVGB M0, X1",
		"PAVGW X0, M1",
		"PAVGB Y0, Y1",
		"PAVGW X0, (AX)",
		"VPAVGB X0, X1",
		"VPAVGW X0, Y1, Y2",
		"VPAVGB X0, X1, (AX)",
		"VPAVGW.BCST 8(AX), X1, X2",
		"VPAVGB.Z X0, X1, X2",
		"VPAVGW X0, X1, K0, X2",
		"VPAVGB X0, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedUnsignedAverageRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PAVGB X8, X0",
		"PAVGW X0, X8",
		"VPAVGB Z8, Z1, Z2",
		"VPAVGW Z0, Z1, Z8",
		"VPAVGB X0, X1, K1, X2",
		"VPAVGW.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedUnsignedAverageRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedUnsignedAverageRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed unsigned-average forms for %s", instruction, goarch)
	}
}
