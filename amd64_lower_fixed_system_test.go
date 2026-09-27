package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestAMD64FixedSystemGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64FixedSystemSpec{
		"CLAC":    {encoding: ".byte 0x0f, 0x01, 0xca"},
		"CLI":     {encoding: ".byte 0xfa"},
		"CLTS":    {encoding: ".byte 0x0f, 0x06"},
		"ENDBR64": {encoding: ".byte 0xf3, 0x0f, 0x1e, 0xfa"},
		"ICEBP":   {encoding: ".byte 0xf1", effect: amd64FixedSystemTrap},
		"INVD":    {encoding: ".byte 0x0f, 0x08"},
		"RSM":     {encoding: ".byte 0x0f, 0xaa", effect: amd64FixedSystemControlTransfer},
		"STAC":    {encoding: ".byte 0x0f, 0x01, 0xcb"},
		"STI":     {encoding: ".byte 0xfb"},
		"SWAPGS":  {encoding: ".byte 0x0f, 0x01, 0xf8"},
		"UD1":     {encoding: ".byte 0x0f, 0xb9, 0x00", effect: amd64FixedSystemTrap},
		"WBINVD":  {encoding: ".byte 0x0f, 0x09"},
	}
	if !reflect.DeepEqual(amd64FixedSystemSpecs, want) {
		t.Fatalf("fixed-system grammar = %+v, want %+v", amd64FixedSystemSpecs, want)
	}
}

func TestTranslateX86FixedSystemCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT fixedsystemforms(SB),$0-0
	CLAC
	CLI
	CLTS
	ENDBR64
	INVD
	STAC
	STI
	SWAPGS
	WBINVD
	RET
TEXT fixedsystemicebp(SB),$0-0
	ICEBP
TEXT fixedsystemrsm(SB),$0-0
	RSM
TEXT fixedsystemud1(SB),$0-0
	UD1
`
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"fixedsystemforms": {Name: "fixedsystemforms", Ret: Void},
					"fixedsystemicebp": {Name: "fixedsystemicebp", Ret: Void},
					"fixedsystemrsm":   {Name: "fixedsystemrsm", Ret: Void},
					"fixedsystemud1":   {Name: "fixedsystemud1", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`.byte 0x0f, 0x01, 0xca`,
				`.byte 0xfa`,
				`.byte 0x0f, 0x06`,
				`.byte 0xf3, 0x0f, 0x1e, 0xfa`,
				`.byte 0x0f, 0x08`,
				`.byte 0x0f, 0x01, 0xcb`,
				`.byte 0xfb`,
				`.byte 0x0f, 0x01, 0xf8`,
				`.byte 0x0f, 0x09`,
				`.byte 0xf1`,
				`.byte 0x0f, 0xaa`,
				`.byte 0x0f, 0xb9, 0x00`,
				`unreachable`,
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			if got := strings.Count(ir, "unreachable"); got != 3 {
				t.Errorf("unreachable count = %d, want 3", got)
			}
			compileLLVMToObject(t, llc, target.triple, "fixed-system-"+target.name+".ll", "fixed-system-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FixedSystemRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "CLAC AX"},
		{goarch: "amd64", instruction: "CLI.P"},
		{goarch: "amd64", instruction: "CLTS AX"},
		{goarch: "amd64", instruction: "ENDBR64 AX"},
		{goarch: "amd64", instruction: "ICEBP AX"},
		{goarch: "amd64", instruction: "INVD AX"},
		{goarch: "amd64", instruction: "RSM AX"},
		{goarch: "amd64", instruction: "STAC AX"},
		{goarch: "amd64", instruction: "STI AX"},
		{goarch: "amd64", instruction: "SWAPGS AX"},
		{goarch: "amd64", instruction: "UD1 AX"},
		{goarch: "amd64", instruction: "WBINVD AX"},
		{goarch: "386", instruction: "ENDBR64.P"},
		{goarch: "386", instruction: "SWAPGS AX"},
	} {
		t.Run(test.goarch+"_"+strings.ReplaceAll(test.instruction, " ", "_"), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's fixed-system tables", test.instruction)
			}
		})
	}
}
