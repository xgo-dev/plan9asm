package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86LegacyPackedEqualityCompleteGoAssemblerForms(t *testing.T) {
	// PCMPEQ{B,W,L} use Go's ymm table (MMX/memory -> MMX and X/memory
	// -> X). PCMPEQQ uses yxm_q4, which has only the X/memory -> X row.
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
			lastX := 15
			if target.goarch == "386" {
				lastX = 7
			}
			var source strings.Builder
			source.WriteString("TEXT legacypackedequalityforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL"} {
				fmt.Fprintf(&source, "\t%s M0, M1\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), M2\n", op)
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, lastX)
				fmt.Fprintf(&source, "\t%s 16(AX), X%d\n", op, lastX)
			}
			fmt.Fprintf(&source, "\tPCMPEQQ X0, X%d\n", lastX)
			fmt.Fprintf(&source, "\tPCMPEQQ 24(AX), X%d\n", lastX)
			source.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"legacypackedequalityforms": {Name: "legacypackedequalityforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "legacy-packed-equality-"+target.name+".ll", "legacy-packed-equality-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86LegacyPackedEqualityRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PCMPEQQ M0, M1",
		"PCMPEQQ X0, M1",
		"PCMPEQW M0, X1",
		"PCMPEQL X0, M1",
		"PCMPEQB Y0, X1",
		"PCMPEQQ X0, Y1",
		"PCMPEQQ.Z X0, X1",
		"PCMPEQQ X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86LegacyPackedEqualityRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86LegacyPackedEqualityRejected(t, "386", "i386-unknown-linux-gnu", "PCMPEQQ X8, X0")
	assertX86LegacyPackedEqualityRejected(t, "386", "i386-unknown-linux-gnu", "PCMPEQQ X0, X8")
}

func assertX86LegacyPackedEqualityRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's legacy packed equality forms", instruction)
	}
}
