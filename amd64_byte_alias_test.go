package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Go 1.27's amd64 Yrb class contains BPB/SIB/DIB and R8B..R15B in
// addition to the four low and four high legacy byte-register spellings.
// REG_SPB is deliberately not classified as Yrb by cmd/internal/obj/x86.
func TestTranslateAMD64ExtendedByteRegisterCompleteGoAssemblerClass(t *testing.T) {
	aliases := []string{"BPB", "SIB", "DIB", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B"}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT extendedbyteforms(SB),NOSPLIT,$0-0\n")
			for _, alias := range aliases {
				fmt.Fprintf(&source, "\tMOVB %s, (AX)\n", alias)
				fmt.Fprintf(&source, "\tMOVB (AX), %s\n", alias)
				fmt.Fprintf(&source, "\tMOVBQZX %s, CX\n", alias)
				fmt.Fprintf(&source, "\tMOVBQSX %s, DX\n", alias)
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"extendedbyteforms": {Name: "extendedbyteforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "extended-byte-"+target.name+".ll", "extended-byte-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ExtendedByteRegisterRejectsFormsOutsideGoAssemblerClass(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			aliases := []string{"SPB"}
			if target.goarch == "386" {
				aliases = append(aliases, "BPB", "SIB", "DIB", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B")
			}
			for _, alias := range aliases {
				instruction := "MOVB " + alias + ", (AX)"
				file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
				if err == nil {
					_, err = Translate(file, Options{
						TargetTriple: target.triple,
						Goarch:       target.goarch,
						Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
					})
				}
				if err == nil {
					t.Fatalf("Translate accepted %q outside Go 1.27's byte-register class for %s", instruction, target.goarch)
				}
			}
		})
	}
}

func TestAMD64ExtendedByteRegisterAliasesShareFullRegisterStorage(t *testing.T) {
	for _, test := range []struct {
		alias Reg
		base  Reg
	}{
		{BPB, BP}, {SIB, SI}, {DIB, DI},
		{R8B, Reg("R8")}, {R9B, Reg("R9")}, {R10B, Reg("R10")}, {R11B, Reg("R11")},
		{R12B, Reg("R12")}, {R13B, Reg("R13")}, {R14B, Reg("R14")}, {R15B, Reg("R15")},
	} {
		base, shift, ok := amd64ByteAlias(test.alias)
		if !ok || base != test.base || shift != 0 {
			t.Errorf("amd64ByteAlias(%s) = (%s, %d, %v), want (%s, 0, true)", test.alias, base, shift, ok, test.base)
		}
	}
}
