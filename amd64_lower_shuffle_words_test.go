package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedWordShuffleCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast := 15
			zLast := 31
			if target.goarch == "386" {
				legacyLast = 7
				zLast = 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedwordshuffleforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PSHUFHW", "PSHUFLW"} {
				fmt.Fprintf(&source, "\t%s $0, X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s $255, 8(AX), X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VPSHUFHW", "VPSHUFLW"} {
				source.WriteString("\t" + op + " $-128, X0, X1\n")
				source.WriteString("\t" + op + " $127, 8(AX), X1\n")
				source.WriteString("\t" + op + " $255, Y0, Y1\n")
				source.WriteString("\t" + op + " $1, 16(AX), Y2\n")
				source.WriteString("\t" + op + " $2, X16, X31\n")
				fmt.Fprintf(&source, "\t%s $3, Z0, Z%d\n", op, zLast)
				if target.goarch == "amd64" {
					source.WriteString("\t" + op + " $4, X20, K1, X21\n")
					source.WriteString("\t" + op + ".Z $5, 24(AX), K2, Y22\n")
					source.WriteString("\t" + op + " $6, Z16, K3, Z31\n")
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
					"packedwordshuffleforms": {Name: "packedwordshuffleforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-word-shuffle-"+target.name+".ll", "packed-word-shuffle-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedWordShuffleRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PSHUFHW $-1, X0, X1",
		"PSHUFLW $256, X0, X1",
		"PSHUFHW $1, X16, X1",
		"PSHUFLW $1, Y0, Y1",
		"PSHUFHW.Z $1, X0, X1",
		"PSHUFLW $1, X0, (AX)",
		"VPSHUFHW $-129, X0, X1",
		"VPSHUFLW $256, X0, X1",
		"VPSHUFHW $-1, X16, X1",
		"VPSHUFLW $-1, Z0, Z1",
		"VPSHUFHW $1, X0, Y1",
		"VPSHUFLW $1, X0, K0, X1",
		"VPSHUFHW.Z $1, X0, X1",
		"VPSHUFLW.BCST $1, (AX), X1",
		"VPSHUFHW $1, X0, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedWordShuffleRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PSHUFHW $1, X8, X0",
		"PSHUFLW $1, X0, X8",
		"VPSHUFHW $1, X0, K1, X1",
		"VPSHUFLW.Z $1, X0, K1, X1",
		"VPSHUFHW $1, Z8, Z0",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedWordShuffleRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedWordShuffleRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's PSHUFHW/PSHUFLW tables for %s", instruction, goarch)
	}
}
