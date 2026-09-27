package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86VMOVDVMOVQCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's _yvmovd and _yvmovq tables allow scalar GP/memory transfers
	// in both directions. VMOVQ additionally allows X-to-X low-qword moves.
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
			source := `TEXT vmovintegerscalarforms(SB),NOSPLIT,$0-0
	VMOVD AX, X0
	VMOVD X0, AX
	VMOVD SP, X1
	VMOVD X1, SP
	VMOVD 8(AX), X20
	VMOVD X20, 12(AX)
	VMOVQ AX, X2
	VMOVQ X2, AX
	VMOVQ SP, X3
	VMOVQ X3, SP
	VMOVQ 16(AX), X30
	VMOVQ X30, 24(AX)
	VMOVQ X0, X1
	VMOVQ X20, X31
`
			if target.goarch == "amd64" {
				source += "\tVMOVD R8, X31\n\tVMOVD X31, R9\n\tVMOVQ R10, X30\n\tVMOVQ X30, R11\n"
			}
			source += "\tRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"vmovintegerscalarforms": {Name: "vmovintegerscalarforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "vmov-integer-scalar-"+target.name+".ll", "vmov-integer-scalar-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86VMOVDVMOVQRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VMOVD X0, X1",
		"VMOVD Y0, AX",
		"VMOVD AX, Y0",
		"VMOVD Z0, AX",
		"VMOVD AX, Z0",
		"VMOVD AX, BX",
		"VMOVD (AX), 8(BX)",
		"VMOVD.Z AX, X0",
		"VMOVD AX, K1, X0",
		"VMOVQ Y0, AX",
		"VMOVQ AX, Y0",
		"VMOVQ Z0, X0",
		"VMOVQ AX, BX",
		"VMOVQ (AX), 8(BX)",
		"VMOVQ.Z X0, X1",
		"VMOVQ X0, K1, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86VMOVIntegerRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VMOVD R8, X0",
		"VMOVD X0, R8",
		"VMOVQ R8, X0",
		"VMOVQ X0, R8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86VMOVIntegerRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86VMOVIntegerRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's VMOVD/VMOVQ forms for %s", instruction, goarch)
	}
}
