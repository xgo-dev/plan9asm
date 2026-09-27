package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestAMD64ImplicitSystemGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64ImplicitSystemSpec{
		"MONITOR":  {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
		"MWAIT":    {inputs: amd64ImplicitAX | amd64ImplicitCX},
		"RDPMC":    {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
		"RDPKRU":   {inputs: amd64ImplicitCX, outputs: amd64ImplicitAX | amd64ImplicitDX},
		"WRPKRU":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
		"XSETBV":   {inputs: amd64ImplicitAX | amd64ImplicitCX | amd64ImplicitDX},
		"UMONITOR": {operand: amd64ImplicitSystemGP},
		"UMWAIT":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true},
		"TPAUSE":   {operand: amd64ImplicitSystemGP, inputs: amd64ImplicitAX | amd64ImplicitDX, writesCarry: true},
	}
	if !reflect.DeepEqual(amd64ImplicitSystemSpecs, want) {
		t.Fatalf("implicit-system grammar = %+v, want %+v", amd64ImplicitSystemSpecs, want)
	}
}

func TestTranslateX86ImplicitSystemCompleteGoAssemblerForms(t *testing.T) {
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
			register := "R11"
			if target.goarch == "386" {
				register = "BX"
			}
			source := "TEXT implicitsystemforms(SB),$0-0\n" +
				"\tMONITOR\n" +
				"\tMWAIT\n" +
				"\tRDPMC\n" +
				"\tRDPKRU\n" +
				"\tWRPKRU\n" +
				"\tXSETBV\n" +
				"\tUMONITOR " + register + "\n" +
				"\tUMWAIT " + register + "\n" +
				"\tTPAUSE " + register + "\n" +
				"\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"implicitsystemforms": {Name: "implicitsystemforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+pku,+waitpkg,+xsave"`,
				`asm sideeffect "monitor"`,
				`asm sideeffect "mwait"`,
				`asm sideeffect "rdpmc"`,
				`asm sideeffect "rdpkru"`,
				`asm sideeffect "wrpkru"`,
				`asm sideeffect "xsetbv"`,
				`asm sideeffect "umonitor $0"`,
				`asm sideeffect "umwait $1; setc $0"`,
				`asm sideeffect "tpause $1; setc $0"`,
				`store i1 %`,
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "implicit-system-"+target.name+".ll", "implicit-system-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ImplicitSystemRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "MONITOR AX"},
		{goarch: "amd64", instruction: "MWAIT.P"},
		{goarch: "amd64", instruction: "RDPMC AX"},
		{goarch: "amd64", instruction: "RDPKRU.P"},
		{goarch: "amd64", instruction: "WRPKRU AX"},
		{goarch: "amd64", instruction: "XSETBV AX"},
		{goarch: "amd64", instruction: "UMONITOR (BX)"},
		{goarch: "amd64", instruction: "UMWAIT X1"},
		{goarch: "amd64", instruction: "TPAUSE"},
		{goarch: "386", instruction: "UMONITOR R11"},
		{goarch: "386", instruction: "UMWAIT R11"},
		{goarch: "386", instruction: "TPAUSE R11"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's implicit-system tables", test.instruction)
			}
		})
	}
}
