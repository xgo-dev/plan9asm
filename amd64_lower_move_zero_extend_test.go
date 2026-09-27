package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedZeroExtendMoveCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast, zLast := 15, 21
			if target.goarch == "386" {
				legacyLast, zLast = 7, 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedzeroextendmoveforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PMOVZXBW", "PMOVZXBD", "PMOVZXBQ", "PMOVZXWD", "PMOVZXWQ", "PMOVZXDQ"} {
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VPMOVZXBW", "VPMOVZXWD", "VPMOVZXDQ"} {
				fmt.Fprintf(&source, "\t%s X0, X1\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), X21\n", op)
				fmt.Fprintf(&source, "\t%s X20, Y21\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), Y21\n", op)
				fmt.Fprintf(&source, "\t%s Y20, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s X20, K1, X21\n", op)
				fmt.Fprintf(&source, "\t%s.Z 8(AX), K2, Y21\n", op)
				fmt.Fprintf(&source, "\t%s.Z Y20, K7, Z%d\n", op, zLast)
			}
			for _, op := range []string{"VPMOVZXBD", "VPMOVZXBQ", "VPMOVZXWQ"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s X20, %s21\n", op, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s21\n", op, width)
					fmt.Fprintf(&source, "\t%s.Z X20, K3, %s21\n", op, width)
				}
				fmt.Fprintf(&source, "\t%s X20, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s.Z 8(AX), K4, Z%d\n", op, zLast)
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
					"packedzeroextendmoveforms": {Name: "packedzeroextendmoveforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-zero-extend-move-"+target.name+".ll", "packed-zero-extend-move-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedZeroExtendMoveRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PMOVZXBW.Z X0, X1",
		"PMOVZXBD X0",
		"PMOVZXBQ M0, X1",
		"PMOVZXWD Y0, X1",
		"PMOVZXWQ X0, Y1",
		"PMOVZXDQ X0, K1, X1",
		"VPMOVZXBW Y0, Y1",
		"VPMOVZXWD X0, Z1",
		"VPMOVZXDQ Z0, Z1",
		"VPMOVZXBD Y0, Z1",
		"VPMOVZXBQ X0, K0, X1",
		"VPMOVZXWQ.Z X0, X1",
		"VPMOVZXBD.BCST 8(AX), X1",
		"VPMOVZXWQ X0, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedZeroExtendMoveRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PMOVZXBW X8, X0",
		"PMOVZXDQ X0, X8",
		"VPMOVZXBW Y20, Z8",
		"VPMOVZXBQ X20, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedZeroExtendMoveRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedZeroExtendMoveRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed zero-extension forms for %s", instruction, goarch)
	}
}
