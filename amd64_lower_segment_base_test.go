package plan9asm

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestAMD64SegmentBaseGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64SegmentBaseSpecs))
	for op := range amd64SegmentBaseSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{
		"RDFSBASEL", "RDFSBASEQ", "RDGSBASEL", "RDGSBASEQ",
		"WRFSBASEL", "WRFSBASEQ", "WRGSBASEL", "WRGSBASEQ",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("segment-base grammar opcodes = %v, want %v", got, want)
	}
	for op, want := range map[Op]amd64SegmentBaseSpec{
		"RDFSBASEL": {segment: FS, direction: amd64SegmentBaseRead, bits: 32},
		"RDFSBASEQ": {segment: FS, direction: amd64SegmentBaseRead, bits: 64},
		"RDGSBASEL": {segment: GS, direction: amd64SegmentBaseRead, bits: 32},
		"RDGSBASEQ": {segment: GS, direction: amd64SegmentBaseRead, bits: 64},
		"WRFSBASEL": {segment: FS, direction: amd64SegmentBaseWrite, bits: 32},
		"WRFSBASEQ": {segment: FS, direction: amd64SegmentBaseWrite, bits: 64},
		"WRGSBASEL": {segment: GS, direction: amd64SegmentBaseWrite, bits: 32},
		"WRGSBASEQ": {segment: GS, direction: amd64SegmentBaseWrite, bits: 64},
	} {
		if got := amd64SegmentBaseSpecs[op]; got != want {
			t.Errorf("segment-base grammar %s = %+v, want %+v", op, got, want)
		}
		if got := want.mnemonic(); strings.ToUpper(got) != string(op) {
			t.Errorf("segment-base grammar %s emits %q", op, got)
		}
	}
}

func TestTranslateX86SegmentBaseCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT segmentbaseforms(SB),$0-0
	RDFSBASEL AX
	RDGSBASEL SP
	WRFSBASEL CX
	WRGSBASEL SP
`
			if target.goarch == "amd64" {
				source += `	RDFSBASEQ R11
	RDGSBASEQ R12
	WRFSBASEQ R13
	WRGSBASEQ R14
`
			}
			source += "\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"segmentbaseforms": {Name: "segmentbaseforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if want := `"target-features"="+fsgsbase"`; !strings.Contains(ir, want) {
				t.Errorf("IR is missing %s:\n%s", want, ir)
			}
			if target.goarch == "386" {
				for _, encoding := range []string{
					".byte 0xf3, 0x0f, 0xae, 0xc0",
					".byte 0xf3, 0x0f, 0xae, 0xc8",
					".byte 0xf3, 0x0f, 0xae, 0xd0",
					".byte 0xf3, 0x0f, 0xae, 0xd8",
				} {
					if !strings.Contains(ir, encoding) {
						t.Errorf("386 IR is missing Go-compatible encoding %q:\n%s", encoding, ir)
					}
				}
			}
			compileLLVMToObject(t, llc, target.triple, "segment-base-"+target.name+".ll", "segment-base-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SegmentBaseRejectsFormsOutsideGoTables(t *testing.T) {
	tests := []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "RDFSBASEL $1"},
		{goarch: "amd64", instruction: "RDFSBASEQ (BX)"},
		{goarch: "amd64", instruction: "RDGSBASEL X0"},
		{goarch: "amd64", instruction: "RDGSBASEQ"},
		{goarch: "amd64", instruction: "WRFSBASEL $1"},
		{goarch: "amd64", instruction: "WRFSBASEQ (BX)"},
		{goarch: "amd64", instruction: "WRGSBASEL X0"},
		{goarch: "amd64", instruction: "WRGSBASEQ.Z AX"},
	}
	for _, op := range []string{
		"RDFSBASEQ", "RDGSBASEQ", "WRFSBASEQ", "WRGSBASEQ",
	} {
		tests = append(tests, struct {
			goarch      string
			instruction string
		}{goarch: "386", instruction: op + " AX"})
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's segment-base tables", test.instruction)
			}
		})
	}
}
