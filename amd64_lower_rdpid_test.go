package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86RDPIDCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		goarch    string
		triple    string
		registers []string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}},
		{goarch: "386", triple: "i686-pc-windows-msvc", registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"}},
		{goarch: "amd64", triple: "x86_64-apple-darwin", registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
		{goarch: "amd64", triple: "x86_64-pc-windows-msvc", registers: []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}},
	} {
		t.Run(target.goarch+"/"+target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rdpidforms(SB),$0-0\n")
			for _, register := range target.registers {
				fmt.Fprintf(&source, "\tRDPID %s\n", register)
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
					"rdpidforms": {Name: "rdpidforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.x86.rdpid()", `"target-features"="+rdpid"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("RDPID lowering omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "x86-rdpid.ll", "x86-rdpid.o", ll)
		})
	}
}

func TestTranslateX86RDPIDRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "386", instruction: "RDPID AL"},
		{goarch: "386", instruction: "RDPID 0(AX)"},
		{goarch: "386", instruction: "RDPID R8"},
		{goarch: "amd64", instruction: "RDPID AL"},
		{goarch: "amd64", instruction: "RDPID 0(AX)"},
		{goarch: "amd64", instruction: "RDPID AX, DX"},
		{goarch: "amd64", instruction: "RDPID.Z AX"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT badrdpid(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs: map[string]FuncSig{
					"badrdpid": {Name: "badrdpid", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go's RDPID optab", test.instruction)
			}
		})
	}
}
