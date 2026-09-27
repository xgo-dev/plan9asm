package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedIntegerMinMaxCompleteGoAssemblerForms(t *testing.T) {
	type operation struct {
		name      string
		broadcast bool
	}
	operations := []operation{
		{name: "VPMINSB"}, {name: "VPMINUB"}, {name: "VPMAXSB"}, {name: "VPMAXUB"},
		{name: "VPMINSW"}, {name: "VPMINUW"}, {name: "VPMAXSW"}, {name: "VPMAXUW"},
		{name: "VPMINSD", broadcast: true}, {name: "VPMINUD", broadcast: true},
		{name: "VPMAXSD", broadcast: true}, {name: "VPMAXUD", broadcast: true},
		{name: "VPMINSQ", broadcast: true}, {name: "VPMINUQ", broadcast: true},
		{name: "VPMAXSQ", broadcast: true}, {name: "VPMAXUQ", broadcast: true},
	}
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
			source.WriteString("TEXT packedintegerminmaxforms(SB),NOSPLIT,$0-0\n")
			for _, operation := range operations {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", operation.name, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20, %s21\n", operation.name, width, width)
					if operation.broadcast {
						fmt.Fprintf(&source, "\t%s.BCST 16(AX), %s20, %s22\n", operation.name, width, width)
					}
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, %s22\n", operation.name, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z 8(AX), %s21, K7, %s22\n", operation.name, width, width)
						if operation.broadcast {
							fmt.Fprintf(&source, "\t%s.BCST.Z 16(AX), %s21, K2, %s22\n", operation.name, width, width)
						}
					}
				}
				fmt.Fprintf(&source, "\t%s Z0, Z6, Z%d\n", operation.name, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, Z%d\n", operation.name, zLast)
				if operation.broadcast {
					fmt.Fprintf(&source, "\t%s.BCST 16(AX), Z6, Z%d\n", operation.name, zLast)
				}
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s Z20, Z21, K3, Z22\n", operation.name)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), Z21, K4, Z22\n", operation.name)
					if operation.broadcast {
						fmt.Fprintf(&source, "\t%s.BCST.Z 16(AX), Z21, K5, Z22\n", operation.name)
					}
				}
			}
			source.WriteString("\tRET\n")
			assembleX87ControlBytes(t, target.goarch, strings.ReplaceAll(source.String(), "NOSPLIT", "4"))
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedintegerminmaxforms": {Name: "packedintegerminmaxforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-integer-minmax-"+target.name+".ll", "packed-integer-minmax-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedIntegerMinMaxRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VPMINUB X0, X1",
		"VPMAXUB X0, X1, (AX)",
		"VPMINSW X0, Y1, X2",
		"VPMAXUW Z0, Z1, Y2",
		"VPMINSD X0, X1, K0, X2",
		"VPMAXUD X0, K1, X1, X2",
		"VPMINSQ.Z X0, X1, X2",
		"VPMAXUQ.SAE X0, X1, X2",
		"VPMINUB.BCST 8(AX), X1, X2",
		"VPMAXSW.BCST 8(AX), X1, X2",
		"VPMINUD.BCST X0, X1, X2",
		"VPMAXSQ.BCST 8(AX), Y1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedIntegerMinMaxRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VPMINUB Z8, Z0, Z1",
		"VPMAXUW Z0, Z8, Z1",
		"VPMINSD Z0, Z1, Z8",
		"VPMAXUQ X0, X1, K1, X2",
		"VPMINSQ.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedIntegerMinMaxRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedIntegerMinMaxRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed min/max forms for %s", instruction, goarch)
	}
}
