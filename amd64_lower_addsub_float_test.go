package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86AlternatingFloatingAddSubtractCompleteGoAssemblerForms(t *testing.T) {
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
			var src strings.Builder
			src.WriteString("TEXT alternatingfloataddsubforms(SB),NOSPLIT,$0-0\n")
			for _, element := range []string{"PS", "PD"} {
				op := "ADDSUB" + element
				fmt.Fprintf(&src, "\t%s X0, X1\n", op)
				fmt.Fprintf(&src, "\t%s (AX), X7\n", op)
				vop := "V" + op
				fmt.Fprintf(&src, "\t%s X0, X1, X2\n", vop)
				fmt.Fprintf(&src, "\t%s (AX), X14, X15\n", vop)
				fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", vop)
				fmt.Fprintf(&src, "\t%s (AX), Y14, Y15\n", vop)
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
					"alternatingfloataddsubforms": {Name: "alternatingfloataddsubforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "alternating-float-addsub-"+target.name+".ll", "alternating-float-addsub-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86AlternatingFloatingAddSubtractRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, op := range []string{"ADDSUBPS", "ADDSUBPD", "VADDSUBPS", "VADDSUBPD"} {
		forms := []string{"X0", "Y0, Y1", "X0, X1, X2"}
		valid := "X0, X1"
		if strings.HasPrefix(op, "V") {
			forms = []string{"X0", "X0, X1", "X0, Y1, Y2", "Z0, Z1, Z2", "X0, X1, K1, X2"}
			valid = "X0, X1, X2"
		}
		for _, operands := range forms {
			instruction := op + " " + operands
			t.Run(strings.NewReplacer(" ", "_", ",", "_").Replace(instruction), func(t *testing.T) {
				assertX86AlternatingAddSubRejected(t, instruction)
			})
		}
		for _, suffix := range []string{".Z", ".BCST", ".SAE", ".RN_SAE"} {
			instruction := op + suffix + " " + valid
			t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
				assertX86AlternatingAddSubRejected(t, instruction)
			})
		}
	}
}

func assertX86AlternatingAddSubRejected(t *testing.T, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's yxm/_yvaddsubpd tables", instruction)
	}
}
