package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86CarryRotateCompleteGoAssemblerForms(t *testing.T) {
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
			widths := []string{"B", "W", "L"}
			if target.goarch == "amd64" {
				widths = append(widths, "Q")
			}
			var source strings.Builder
			source.WriteString("TEXT carryrotateforms(SB),NOSPLIT,$0-0\n")
			for _, stem := range []string{"RCL", "RCR"} {
				for _, width := range widths {
					op := stem + width
					reg := "AX"
					if width == "B" {
						reg = "AH"
					}
					fmt.Fprintf(&source, "\t%s $1, %s\n", op, reg)
					fmt.Fprintf(&source, "\t%s $255, 8(BX)\n", op)
					fmt.Fprintf(&source, "\t%s CL, %s\n", op, reg)
					fmt.Fprintf(&source, "\t%s CX, 16(BX)\n", op)
				}
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
					"carryrotateforms": {Name: "carryrotateforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "carry-rotate-"+target.name+".ll", "carry-rotate-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86CarryRotateRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"RCLB $-1, AL",
		"RCRW $256, AX",
		"RCLL AX, BX",
		"RCRQ (AX), BX",
		"RCLQ $1, X0",
		"RCRB.Z $1, AL",
		"RCLL $1, AX, BX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86CarryRotateRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"RCLQ $1, AX",
		"RCRQ CL, (BX)",
		"RCLB $1, SP",
		"RCRL $1, R8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86CarryRotateRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86CarryRotateRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's RCL/RCR tables for %s", instruction, goarch)
	}
}
