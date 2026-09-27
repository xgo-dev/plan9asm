package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86MoveHalfCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		goarch string
		triple string
		last   int
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", last: 15},
		{goarch: "386", triple: "i386-unknown-linux-gnu", last: 7},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT movehalfforms(SB),$0-0\n")
			for _, op := range []string{"MOVLPS", "MOVHPS", "MOVLPD", "MOVHPD"} {
				fmt.Fprintf(&source, "\t%s X1, X%d\n", op, target.last)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, target.last)
				fmt.Fprintf(&source, "\t%s X%d, 16(BX)\n", op, target.last)
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"movehalfforms": {Name: "movehalfforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "extractelement <2 x i64>") || !strings.Contains(ll, "insertelement <2 x i64>") {
				t.Fatalf("translation omitted half-vector lane operations:\n%s", ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "move-half-"+target.goarch+".ll", "move-half-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86MoveHalfRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"MOVHPS Y0, X1",
		"MOVLPS X0, Y1",
		"MOVHPD (AX), (BX)",
		"MOVLPD $1, X0",
		"MOVHPS.Z X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's yxmov table", instruction)
			}
		})
	}
}
