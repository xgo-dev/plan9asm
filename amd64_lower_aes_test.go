package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86AESCompleteGoAssemblerForms(t *testing.T) {
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
			zLast := 31
			if target.goarch == "386" {
				legacyLast = 7
				zLast = 7
			}
			var source strings.Builder
			source.WriteString("TEXT aesforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST"} {
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
				vop := "V" + op
				source.WriteString("\t" + vop + " X0, X1, X2\n")
				source.WriteString("\t" + vop + " 16(AX), X1, X2\n")
				source.WriteString("\t" + vop + " Y0, Y1, Y2\n")
				source.WriteString("\t" + vop + " 32(AX), Y1, Y2\n")
				source.WriteString("\t" + vop + " X16, X30, X31\n")
				fmt.Fprintf(&source, "\t%s Z0, Z1, Z%d\n", vop, zLast)
			}
			fmt.Fprintf(&source, "\tAESIMC X0, X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tAESIMC 8(AX), X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tVAESIMC X0, X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tVAESIMC 8(AX), X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tAESKEYGENASSIST $0, X0, X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tAESKEYGENASSIST $255, 8(AX), X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tVAESKEYGENASSIST $-128, X0, X%d\n", legacyLast)
			fmt.Fprintf(&source, "\tVAESKEYGENASSIST $255, 8(AX), X%d\n", legacyLast)
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"aesforms": {Name: "aesforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "aes-"+target.name+".ll", "aes-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86AESRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"AESENC Y0, X1",
		"AESENC X0, X16",
		"AESENC.Z X0, X1",
		"AESIMC X0, (AX)",
		"AESKEYGENASSIST $-1, X0, X1",
		"AESKEYGENASSIST $256, X0, X1",
		"VAESENC X0, Y1, Y2",
		"VAESENC X0, X1",
		"VAESENC X0, X1, K1, X2",
		"VAESENC.Z X0, X1, X2",
		"VAESENC X0, X1, (AX)",
		"VAESIMC Y0, Y1",
		"VAESIMC X16, X1",
		"VAESKEYGENASSIST $-129, X0, X1",
		"VAESKEYGENASSIST $256, X0, X1",
		"VAESKEYGENASSIST $1, Y0, Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86AESRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"AESENC X8, X0",
		"AESIMC X0, X8",
		"AESKEYGENASSIST $1, X8, X0",
		"VAESIMC X8, X0",
		"VAESKEYGENASSIST $1, X0, X8",
		"VAESENC Z8, Z0, Z1",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86AESRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86AESRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's AES/VAES tables for %s", instruction, goarch)
	}
}
