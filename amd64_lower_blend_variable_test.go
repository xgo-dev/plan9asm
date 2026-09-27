package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86VariableBlendCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's yblendvpd and _yvblendvpd tables are shared by the
	// PS (dword lanes), PD (qword lanes), and PBLENDVB (byte lanes) variants.
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
			if target.goarch == "386" {
				legacyLast = 7
			}
			var src strings.Builder
			src.WriteString("TEXT variableblendforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"BLENDVPS", "BLENDVPD", "PBLENDVB"} {
				fmt.Fprintf(&src, "\t%s X0, (AX), X1\n", op)
				fmt.Fprintf(&src, "\t%s X0, X2, X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VBLENDVPS", "VBLENDVPD", "VPBLENDVB"} {
				fmt.Fprintf(&src, "\t%s X0, (AX), X1, X2\n", op)
				fmt.Fprintf(&src, "\t%s X12, X13, X14, X15\n", op)
				fmt.Fprintf(&src, "\t%s Y0, 32(AX), Y1, Y2\n", op)
				fmt.Fprintf(&src, "\t%s Y12, Y13, Y14, Y15\n", op)
			}
			src.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"variableblendforms": {Name: "variableblendforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "variable-blend-"+target.name+".ll", "variable-blend-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86VariableBlendRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"BLENDVPS X1, X2, X3",
		"BLENDVPD X0, Y1, X2",
		"PBLENDVB X0, X1, Y2",
		"BLENDVPS.Z X0, X1, X2",
		"VBLENDVPS X0, X1, X2",
		"VBLENDVPD X0, X1, X2, X3, X4",
		"VPBLENDVB (AX), X1, X2, X3",
		"VBLENDVPS X0, Y1, X2, X3",
		"VBLENDVPD Y0, Y1, X2, Y3",
		"VPBLENDVB Y0, Y1, Y2, X3",
		"VBLENDVPS.Z X0, X1, X2, X3",
		"VBLENDVPD X16, X1, X2, X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86VariableBlendRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"BLENDVPS X0, X8, X1",
		"BLENDVPD X0, X1, X8",
		"PBLENDVB X8, X1, X2",
	} {
		assertX86VariableBlendRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86VariableBlendRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's variable blend tables", instruction)
	}
}
