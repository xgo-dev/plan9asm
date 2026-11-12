package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestAMD64SystemTransferGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64SystemTransferSpec{
		"SYSENTER":   {kind: amd64SystemEnter},
		"SYSENTER64": {kind: amd64SystemEnter, mode64: true},
		"SYSEXIT":    {kind: amd64SystemExit, inputs: amd64SystemTransferCX | amd64SystemTransferDX},
		"SYSEXIT64":  {kind: amd64SystemExit, mode64: true, inputs: amd64SystemTransferCX | amd64SystemTransferDX},
		"SYSRET":     {kind: amd64SystemReturn, inputs: amd64SystemTransferCX | amd64SystemTransferR11},
	}
	if !reflect.DeepEqual(amd64SystemTransferSpecs, want) {
		t.Fatalf("system-transfer grammar = %+v, want %+v", amd64SystemTransferSpecs, want)
	}
}

func TestTranslateX86SystemTransferCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT sysenterform(SB),$0-0
	SYSENTER
	RET
TEXT sysexitform(SB),$0-0
	SYSEXIT
TEXT sysretform(SB),$0-0
	SYSRET
`
			sigs := map[string]FuncSig{
				"sysenterform": {Name: "sysenterform", Ret: Void},
				"sysexitform":  {Name: "sysexitform", Ret: Void},
				"sysretform":   {Name: "sysretform", Ret: Void},
			}
			if target.goarch == "amd64" {
				source += `TEXT sysenter64form(SB),$0-0
	SYSENTER64
	RET
TEXT sysexit64form(SB),$0-0
	SYSEXIT64
`
				sigs["sysenter64form"] = FuncSig{Name: "sysenter64form", Ret: Void}
				sigs["sysexit64form"] = FuncSig{Name: "sysexit64form", Ret: Void}
			}
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`.byte 0x0f, 0x34`,
				`.byte 0x0f, 0x35`,
				`.byte 0x0f, 0x07`,
				`{cx},{dx},~{memory}`,
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			wantUnreachable := 2
			if target.goarch == "amd64" {
				wantUnreachable = 3
				for _, want := range []string{
					`.byte 0x48, 0x0f, 0x34`,
					`.byte 0x48, 0x0f, 0x35`,
					`{cx},{r11},~{memory}`,
				} {
					if !strings.Contains(ir, want) {
						t.Errorf("amd64 IR is missing %s:\n%s", want, ir)
					}
				}
			}
			if got := strings.Count(ir, "unreachable"); got != wantUnreachable {
				t.Errorf("unreachable count = %d, want %d", got, wantUnreachable)
			}
			compileLLVMToObject(t, llc, target.triple, "system-transfer-"+target.name+".ll", "system-transfer-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SystemTransferRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "SYSENTER AX"},
		{goarch: "amd64", instruction: "SYSENTER64.P"},
		{goarch: "amd64", instruction: "SYSEXIT AX"},
		{goarch: "amd64", instruction: "SYSEXIT64 AX"},
		{goarch: "amd64", instruction: "SYSRET AX"},
		{goarch: "386", instruction: "SYSENTER64"},
		{goarch: "386", instruction: "SYSEXIT64"},
		{goarch: "386", instruction: "SYSRET.P"},
	} {
		t.Run(test.goarch+"_"+strings.ReplaceAll(test.instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n"
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
				t.Fatalf("Translate accepted %q outside Go 1.27's system-transfer tables", test.instruction)
			}
		})
	}
}
