package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedLogicalShiftCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast, zLast := 15, 22
			if target.goarch == "386" {
				legacyLast, zLast = 7, 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedlogicalshiftforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PSLLW", "PSLLL", "PSLLQ", "PSRLW", "PSRLL", "PSRLQ"} {
				fmt.Fprintf(&source, "\t%s $-1, M1\n", op)
				fmt.Fprintf(&source, "\t%s M0, M1\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), M1\n", op)
				fmt.Fprintf(&source, "\t%s $3, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VPSLLW", "VPSLLD", "VPSLLQ", "VPSRLW", "VPSRLD", "VPSRLQ"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&source, "\t%s $-1, %s20, %s21\n", op, width, width)
					fmt.Fprintf(&source, "\t%s $255, 8(AX), %s21\n", op, width)
					fmt.Fprintf(&source, "\t%s X0, %s20, %s21\n", op, width, width)
					fmt.Fprintf(&source, "\t%s 8(AX), %s20, %s21\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s $3, %s20, K1, %s22\n", op, width, width)
						fmt.Fprintf(&source, "\t%s.Z X0, %s20, K7, %s22\n", op, width, width)
					}
				}
				fmt.Fprintf(&source, "\t%s $3, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s $3, 8(AX), Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s X0, Z6, Z%d\n", op, zLast)
				fmt.Fprintf(&source, "\t%s 8(AX), Z6, Z%d\n", op, zLast)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $3, Z20, K2, Z22\n", op)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), Z20, K6, Z22\n", op)
				}
				if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), X21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), Y21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST $3, 8(AX), Z%d\n", op, zLast)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.BCST.Z $3, 8(AX), K5, Z22\n", op)
					}
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
					"packedlogicalshiftforms": {Name: "packedlogicalshiftforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-logical-shift-"+target.name+".ll", "packed-logical-shift-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedLogicalShiftRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PSLLW.Z $3, X0",
		"PSLLL $3",
		"PSLLQ $-129, X0",
		"PSRLW $128, X0",
		"PSRLL M0, X1",
		"PSRLQ X0, M1",
		"VPSLLW $-129, X0, X1",
		"VPSLLD $256, X0, X1",
		"VPSLLQ Y0, X1, X2",
		"VPSRLW X0, 8(AX), X2",
		"VPSRLD Y0, X1, X2",
		"VPSRLQ.BCST X0, X1, X2",
		"VPSLLW.BCST $3, 8(AX), X2",
		"VPSLLD.BCST $3, X1, X2",
		"VPSRLQ.Z $3, X1, X2",
		"VPSLLQ $3, X1, K0, X2",
		"VPSRLD $3, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedLogicalShiftRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PSLLQ X8, X0",
		"PSRLQ X0, X8",
		"VPSLLQ $3, Z8, Z1",
		"VPSRLQ X0, Z1, Z8",
		"VPSLLD $3, X1, K1, X2",
		"VPSRLD.Z X0, X1, K1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedLogicalShiftRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedLogicalShiftRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed logical-shift forms for %s", instruction, goarch)
	}
}
