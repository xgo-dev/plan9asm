package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86ImplicitMaskMoveCompleteGoAssemblerForms(t *testing.T) {
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
			source := fmt.Sprintf("TEXT implicitmaskmoveforms(SB),NOSPLIT,$0-0\n"+
				"\tMASKMOVQ M0, M7\n"+
				"\tMASKMOVOU X0, X%d\n"+
				"\tMASKMOVDQU X0, X%d\n"+
				"\tVMASKMOVDQU X0, X%d\n"+
				"\tRET\n", last, last, last)
			// Preserve all four original rows and their actual Go objects.
			// These bare registers/DI cannot establish a successful public
			// translation. The independently initialized full-family root
			// compiles real translated objects at the same five targets.
			file, _ := x86UnboundVoidFormatSources(t, source, target.goarch, target.triple)
			count := 0
			for _, instruction := range file.Funcs[0].Instrs {
				if instruction.Op == OpTEXT || instruction.Op == OpRET {
					continue
				}
				if _, known, err := x86ImplicitMaskMoveProperties(instruction.Op, instruction, target.goarch); !known || err != nil {
					t.Fatal("original implicit mask-store format disappeared", instruction.Raw, err)
				}
				count++
			}
			if count != 4 {
				t.Fatal("original complete implicit mask-store denominator changed", count)
			}
		})
	}
}

func TestTranslateX86ImplicitMaskMoveRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"MASKMOVQ.Z M0, M1",
		"MASKMOVQ M0",
		"MASKMOVQ M0, X1",
		"MASKMOVQ 8(AX), M1",
		"MASKMOVOU.Z X0, X1",
		"MASKMOVOU X0",
		"MASKMOVOU M0, M1",
		"MASKMOVOU X0, Y1",
		"MASKMOVDQU.Z X0, X1",
		"MASKMOVDQU X0, X1, X2",
		"MASKMOVDQU 8(AX), X1",
		"VMASKMOVDQU.Z X0, X1",
		"VMASKMOVDQU X0",
		"VMASKMOVDQU Y0, Y1",
		"VMASKMOVDQU X0, K1, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86ImplicitMaskMoveRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"MASKMOVOU X8, X0",
		"MASKMOVDQU X0, X8",
		"VMASKMOVDQU X8, X0",
		"VMASKMOVDQU X0, X8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86ImplicitMaskMoveRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86ImplicitMaskMoveRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's implicit mask-move forms for %s", instruction, goarch)
	}
}
