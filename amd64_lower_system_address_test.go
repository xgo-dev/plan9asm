package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestAMD64SystemAddressGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64SystemAddressSpec{
		"INVLPG":   {kind: amd64SystemAddressInvalidatePage, memoryBytes: 1},
		"INVPCID":  {kind: amd64SystemAddressInvalidatePCID, memoryBytes: 16, register: true},
		"CLDEMOTE": {kind: amd64SystemAddressDemoteCacheLine, memoryBytes: 1},
	}
	if !reflect.DeepEqual(amd64SystemAddressSpecs, want) {
		t.Fatalf("system-address grammar = %+v, want %+v", amd64SystemAddressSpecs, want)
	}
}

func TestTranslateX86SystemAddressCompleteGoAssemblerForms(t *testing.T) {
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
			base := "BX"
			if target.goarch == "amd64" {
				base = "R11"
			}
			source := "TEXT systemaddressforms(SB),$0-0\n" +
				"\tINVLPG 8(" + base + ")\n" +
				"\tCLDEMOTE 16(" + base + ")\n" +
				"\tINVPCID 32(" + base + "), AX\n" +
				"\tRET\n" +
				"TEXT invlpgcompat(SB),$0-0\n\tINVLPG AX\n" +
				"TEXT invpcidcompat(SB),$0-0\n\tINVPCID AX, BX\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"systemaddressforms": {Name: "systemaddressforms", Ret: Void},
					"invlpgcompat":       {Name: "invlpgcompat", Ret: Void},
					"invpcidcompat":      {Name: "invpcidcompat", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+cldemote,+invpcid"`, `asm sideeffect "ud2"`, "unreachable"} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			if target.goarch == "386" && !strings.Contains(ir, ".byte 0x66, 0x0f, 0x38, 0x82, 0x03") {
				t.Errorf("386 IR is missing Go-compatible INVPCID encoding:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "system-address-"+target.name+".ll", "system-address-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SystemAddressRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "INVLPG X1"},
		{goarch: "amd64", instruction: "INVLPG.Z (BX)"},
		{goarch: "amd64", instruction: "CLDEMOTE AX"},
		{goarch: "amd64", instruction: "CLDEMOTE (BX), (CX)"},
		{goarch: "amd64", instruction: "INVPCID (BX), X1"},
		{goarch: "amd64", instruction: "INVPCID X1, BX"},
		{goarch: "amd64", instruction: "INVPCID (BX)"},
		{goarch: "386", instruction: "INVLPG (R11)"},
		{goarch: "386", instruction: "CLDEMOTE (R11)"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's system-address tables", test.instruction)
			}
		})
	}
}
