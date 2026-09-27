package plan9asm

import (
	"fmt"
	"testing"
)

func TestTranslateX86PackedQwordMultiplyCompleteGoAssemblerForms(t *testing.T) {
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
			lastZ := 20
			if target.goarch == "386" {
				lastZ = 7
			}
			source := fmt.Sprintf(`
TEXT packedqwordmultiplyforms(SB),NOSPLIT,$0-0
	VPMULLQ X1, X20, X21
	VPMULLQ 8(AX), Y20, Y21
	VPMULLQ Z1, Z2, Z%d
	VPMULLQ.BCST 40(AX), X20, X21
	VPMULLQ.BCST 48(AX), Y20, Y21
	VPMULLQ.BCST 56(AX), Z2, Z%d
`, lastZ, lastZ)
			if target.goarch == "amd64" {
				source += `
	VPMULLQ X1, X20, K1, X21
	VPMULLQ.Z Y1, Y20, K2, Y21
	VPMULLQ.BCST.Z 104(AX), Z20, K3, Z21
`
			}
			source += "\tRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"packedqwordmultiplyforms": {Name: "packedqwordmultiplyforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-qword-multiply-"+target.name+".ll", "packed-qword-multiply-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedQwordMultiplyRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPMULLQ X0, X1",
		"VPMULLQ X0, Y1, Y2",
		"VPMULLQ X0, (AX), X2",
		"VPMULLQ X0, X1, K0, X2",
		"VPMULLQ X0, X1, AX",
		"VPMULLQ.Z X0, X1, X2",
		"VPMULLQ.BCST X0, X1, X2",
		"VPMULLQ.Z.BCST (AX), X1, K1, X2",
		"VPMULLQ.RN_SAE X0, X1, X2",
	} {
		assertX86PackedQwordMultiplyRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
	}
	assertX86PackedQwordMultiplyRejected(t, "386", "i386-unknown-linux-gnu", "VPMULLQ X0, X1, K1, X2")
	assertX86PackedQwordMultiplyRejected(t, "386", "i386-unknown-linux-gnu", "VPMULLQ Z0, Z1, Z8")
}

func assertX86PackedQwordMultiplyRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's VPMULLQ forms", instruction)
	}
}
