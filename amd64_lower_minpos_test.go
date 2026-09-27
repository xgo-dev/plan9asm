package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedUnsignedWordMinimumPositionCompleteGoAssemblerForms(t *testing.T) {
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
			source := fmt.Sprintf("TEXT packedminimumpositionforms(SB),NOSPLIT,$0-0\n"+
				"\tPHMINPOSUW X0, X%d\n"+
				"\tPHMINPOSUW 8(AX), X%d\n"+
				"\tVPHMINPOSUW X0, X%d\n"+
				"\tVPHMINPOSUW 8(AX), X%d\n"+
				"\tRET\n", last, last, last, last)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedminimumpositionforms": {Name: "packedminimumpositionforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-minimum-position-"+target.name+".ll", "packed-minimum-position-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedUnsignedWordMinimumPositionRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PHMINPOSUW.Z X0, X1",
		"PHMINPOSUW X0",
		"PHMINPOSUW M0, M1",
		"PHMINPOSUW Y0, Y1",
		"PHMINPOSUW X0, (AX)",
		"VPHMINPOSUW.Z X0, X1",
		"VPHMINPOSUW X0",
		"VPHMINPOSUW X0, X1, X2",
		"VPHMINPOSUW Y0, Y1",
		"VPHMINPOSUW Z0, Z1",
		"VPHMINPOSUW X0, K1, X1",
		"VPHMINPOSUW X0, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedUnsignedWordMinimumPositionRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PHMINPOSUW X8, X0",
		"PHMINPOSUW X0, X8",
		"VPHMINPOSUW X16, X0",
		"VPHMINPOSUW X0, X16",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedUnsignedWordMinimumPositionRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedUnsignedWordMinimumPositionRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's PHMINPOSUW forms for %s", instruction, goarch)
	}
}
