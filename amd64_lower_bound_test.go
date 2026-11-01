package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslate386BoundCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "linux-386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			source := "TEXT boundforms(SB),NOSPLIT,$16-0\n"
			for _, op := range []string{"BOUNDW", "BOUNDL"} {
				for _, reg := range []string{"AX", "BX", "CX", "DX", "SP", "BP", "SI", "DI"} {
					source += "\t" + op + " " + reg + ", 0(SP)\n"
				}
				source += "\t" + op + " AX, 8(BX)\n"
			}
			source += "\tRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"boundforms": {Name: "boundforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{".byte 0x66, 0x62, 0x01", ".byte 0x62, 0x01", `"{ax},{cx},~{memory},~{dirflag},~{fpsr},~{flags}"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("translated BOUND family missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "bound-"+target.name+".ll", "bound-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86BoundRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	tests := []struct {
		goarch      string
		triple      string
		instruction string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "BOUNDW AX, 0(BX)"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "BOUNDL AX, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL X0, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDW $1, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL AX, BX"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "BOUNDL.Z AX, 0(BX)"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+test.instruction+"\n\tRET\n")
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: test.triple,
					Goarch:       test.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's BOUND tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
