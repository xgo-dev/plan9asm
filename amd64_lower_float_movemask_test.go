package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86FloatingMoveMaskCompleteGoAssemblerForms(t *testing.T) {
	// MOVMSK{PS,PD} uses Go's legacy yxrrl table (X -> Yrl), while the
	// VMOVMSK forms use _yvmovmskpd (X/Y -> Yrl). Neither table accepts
	// memory, EVEX registers, masks, or opcode suffixes.
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
			lastLegacyX := 15
			if target.goarch == "386" {
				lastLegacyX = 7
			}
			source := fmt.Sprintf(`
TEXT floatingmovemaskforms(SB),NOSPLIT,$0-0
	MOVMSKPS X%d, AX
	MOVMSKPD X%d, BX
	VMOVMSKPS X15, CX
	VMOVMSKPS Y15, DX
	VMOVMSKPD X15, SI
	VMOVMSKPD Y15, DI
	RET
`, lastLegacyX, lastLegacyX)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"floatingmovemaskforms": {Name: "floatingmovemaskforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "floating-movemask-"+target.name+".ll", "floating-movemask-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86FloatingMoveMaskRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"MOVMSKPS Y0, AX",
		"MOVMSKPD (AX), BX",
		"MOVMSKPS X16, AX",
		"VMOVMSKPS Z0, AX",
		"VMOVMSKPD X16, AX",
		"VMOVMSKPS Y16, AX",
		"VMOVMSKPD (AX), BX",
		"VMOVMSKPS X0, X1",
		"VMOVMSKPD X0, K1, AX",
		"MOVMSKPS.Z X0, AX",
		"VMOVMSKPD.BCST Y0, AX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86FloatingMoveMaskRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86FloatingMoveMaskRejected(t, "386", "i386-unknown-linux-gnu", "MOVMSKPS X8, AX")
}

func assertX86FloatingMoveMaskRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's floating movemask forms", instruction)
	}
}
