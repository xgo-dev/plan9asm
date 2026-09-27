package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedDotProductCompleteGoAssemblerForms(t *testing.T) {
	// These four opcodes share Go 1.27's six-row _yvblendmpd table. Each
	// width accepts register/memory source 2, register source 1, and an
	// accumulator destination; amd64 additionally accepts K1-K7 merge/.Z.
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
			zLast := 22
			if target.goarch == "386" {
				zLast = 7
			}
			var source strings.Builder
			source.WriteString("TEXT packeddotproductforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VPDPBUSD", "VPDPBUSDS", "VPDPWSSD", "VPDPWSSDS"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20, %s21\n", op, width, width)
					fmt.Fprintf(&source, "\t%s.BCST 12(AX), %s20, %s22\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, %s22\n", op, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z 8(AX), %s21, K7, %s22\n", op, width, width)
						fmt.Fprintf(&source, "\t%s.BCST.Z 12(AX), %s21, K2, %s22\n", op, width, width)
					}
				}
				fmt.Fprintf(&source, "\t%s Z0, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s.BCST 12(AX), Z6, Z%d\n", op, zLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s Z20, Z21, K3, Z22\n", op)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), Z21, K4, Z22\n", op)
					fmt.Fprintf(&source, "\t%s.BCST.Z 12(AX), Z21, K5, Z22\n", op)
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
					"packeddotproductforms": {Name: "packeddotproductforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-dot-product-"+target.name+".ll", "packed-dot-product-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedDotProductRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPDPBUSD X0, X1",
		"VPDPBUSDS X0, X1, (AX)",
		"VPDPWSSD X0, Y1, X2",
		"VPDPWSSDS Z0, Z1, Y2",
		"VPDPBUSD X0, X1, K0, X2",
		"VPDPBUSD X0, K1, X1, X2",
		"VPDPBUSD.Z X0, X1, X2",
		"VPDPBUSDS.SAE X0, X1, X2",
		"VPDPWSSD.BCST X0, X1, X2",
		"VPDPWSSDS.BCST 8(AX), Y1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedDotProductRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VPDPBUSD Z8, Z0, Z1",
		"VPDPBUSDS Z0, Z8, Z1",
		"VPDPWSSD Z0, Z1, Z8",
		"VPDPWSSDS X0, X1, K1, X2",
		"VPDPBUSD.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedDotProductRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedDotProductRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's _yvblendmpd forms for %s", instruction, goarch)
	}
}
