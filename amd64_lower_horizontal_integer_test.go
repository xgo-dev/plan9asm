package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86HorizontalIntegerCompleteGoAssemblerForms(t *testing.T) {
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
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			source.WriteString("TEXT horizontalintegerforms(SB),NOSPLIT,$0-0\n")
			// PHADDD uniquely uses Go's ymmxmm0f38 table and therefore has
			// both MMX/m64 and XMM/m128 legacy rows.
			source.WriteString("\tPHADDD M0, M1\n\tPHADDD 8(AX), M2\n")
			for _, op := range []string{"PHADDD", "PHADDSW", "PHADDW", "PHSUBD", "PHSUBSW", "PHSUBW"} {
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, last)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, last)
				vector := "V" + op
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s%d\n", vector, width, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(AX), %s1, %s%d\n", vector, width, width, last)
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
					"horizontalintegerforms": {Name: "horizontalintegerforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "horizontal-integer-"+target.name+".ll", "horizontal-integer-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86HorizontalIntegerRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PHADDD.Z X0, X1",
		"PHADDD X0",
		"PHADDSW M0, M1",
		"PHADDW M0, M1",
		"PHSUBD M0, M1",
		"PHSUBSW M0, M1",
		"PHSUBW M0, M1",
		"PHADDW X0, M1",
		"PHSUBD Y0, Y1",
		"VPHADDD.Z X0, X1, X2",
		"VPHADDSW X0, X1",
		"VPHADDW X0, Y1, Y2",
		"VPHSUBD Z0, Z1, Z2",
		"VPHSUBSW X0, X1, K1, X2",
		"VPHSUBW X0, X1, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86HorizontalIntegerRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PHADDD X8, X0",
		"PHADDW X0, X8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86HorizontalIntegerRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86HorizontalIntegerRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's horizontal-integer forms for %s", instruction, goarch)
	}
}
