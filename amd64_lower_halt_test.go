package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86HLTCompleteGoAssemblerForms(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT haltforms(SB),NOSPLIT,$0-0\n\tHLT\n")
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
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
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"haltforms": {Name: "haltforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, `asm sideeffect "hlt"`) || !strings.Contains(ll, "unreachable") {
				t.Fatalf("HLT must retain the hardware instruction and terminate control flow:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "hlt-"+target.name+".ll", "hlt-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86HLTRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{"HLT AX", "HLT $1", "HLT.P"} {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's HLT ynone table", instruction)
		}
	}
}
