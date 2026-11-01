package plan9asm

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAMD64FarPointerGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64FarPointerSpecs))
	for op := range amd64FarPointerSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{"LFSL", "LFSQ", "LFSW", "LGSL", "LGSQ", "LGSW", "LSSL", "LSSQ", "LSSW"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("far-pointer grammar opcodes = %v, want %v", got, want)
	}
}

func TestTranslateX86FarPointerCompleteGoAssemblerForms(t *testing.T) {
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
			destination := "DI"
			base := "BX"
			if target.goarch == "amd64" {
				destination = "R12"
				base = "R13"
			}
			source := "TEXT farpointerforms(SB),$0-0\n"
			for _, family := range []string{"LFS", "LGS", "LSS"} {
				source += "\t" + family + "W 0(BX), AX\n"
				source += "\t" + family + "W 2(" + base + "), " + destination + "\n"
				source += "\t" + family + "L 4(BX), DX\n"
				if target.goarch == "amd64" {
					source += "\t" + family + "Q 8(" + base + "), " + destination + "\n"
				} else {
					source += "\t" + family + "L 8(BX), SP\n"
				}
			}
			source += "\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"farpointerforms": {Name: "farpointerforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "far-pointer-"+target.name+".ll", "far-pointer-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FarPointerRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LFSW AX, DX"},
		{goarch: "amd64", instruction: "LFSL (BX), (CX)"},
		{goarch: "amd64", instruction: "LGSQ (BX), X0"},
		{goarch: "amd64", instruction: "LSSW.Z (BX), DX"},
		{goarch: "386", instruction: "LFSQ (BX), AX"},
		{goarch: "386", instruction: "LGSL (R11), AX"},
		{goarch: "386", instruction: "LSSL (BX), R11"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
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
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's far-pointer tables", test.instruction)
			}
		})
	}
}
