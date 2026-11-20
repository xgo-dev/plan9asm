package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedIntegerInsertCompleteGoAssemblerForms(t *testing.T) {
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
			var source strings.Builder
			source.WriteString("TEXT packedintegerinsertforms(SB),$0-0\n")
			legacyOps := []string{"PINSRB", "PINSRW", "PINSRD", "PINSRQ"}
			vectorOps := []string{"VPINSRB", "VPINSRW", "VPINSRD", "VPINSRQ"}
			if target.goarch == "386" {
				legacyOps = legacyOps[:3]
				vectorOps = nil
			}
			for _, op := range legacyOps {
				fmt.Fprintf(&source, "\t%s $0, AX, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s $255, 8(AX), X%d\n", op, legacyLast)
			}
			for _, op := range vectorOps {
				fmt.Fprintf(&source, "\t%s $0, AX, X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s $255, 8(AX), X0, X%d\n", op, legacyLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $82, R9, X22, X31\n", op)
				}
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
				Sigs: map[string]FuncSig{
					"packedintegerinsertforms": {Name: "packedintegerinsertforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-integer-insert.ll", "packed-integer-insert.o", ll)
		})
	}
}

func TestTranslateX86PackedIntegerInsertRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PINSRB $-1, AX, X0",
		"PINSRW $256, AX, X0",
		"PINSRD $1, AX, Y0",
		"PINSRQ.Z $1, AX, X0",
		"PINSRB $1, AL, X0",
		"PINSRD $1, X0, X1",
		"PINSRQ $1, AX, X16",
		"VPINSRB $1, AX, X0, Y1",
		"VPINSRW $1, AX, Y0, X1",
		"VPINSRD $1, X0, X1, X2",
		"VPINSRQ $1, AX, X0, K1, X1",
		"VPINSRQ.Z $1, AX, X0, X1",
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
				t.Fatalf("Translate accepted %q outside Go 1.27's PINSR/VPINSR tables", instruction)
			}
		})
	}

	for _, instruction := range []string{
		"PINSRQ $1, AX, X0",
		"VPINSRB $1, AX, X0, X1",
		"VPINSRQ $1, AX, X0, X1",
		"PINSRD $1, R8, X0",
		"PINSRD $1, AX, X8",
	} {
		t.Run("386_"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's 386 PINSR/VPINSR tables", instruction)
			}
		})
	}
}
