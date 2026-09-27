package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestAMD64FarReturnGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64FarReturnSpec{
		"IRETW": {kind: amd64InterruptReturn, bits: 16},
		"IRETL": {kind: amd64InterruptReturn, bits: 32},
		"IRETQ": {kind: amd64InterruptReturn, bits: 64},
		"RETFW": {kind: amd64FarReturn, bits: 16, allowImmediate: true},
		"RETFL": {kind: amd64FarReturn, bits: 32, allowImmediate: true},
		"RETFQ": {kind: amd64FarReturn, bits: 64, allowImmediate: true},
	}
	if !reflect.DeepEqual(amd64FarReturnSpecs, want) {
		t.Fatalf("far-return grammar = %+v, want %+v", amd64FarReturnSpecs, want)
	}
}

func TestAMD64FarReturnSplitsFollowingInstructions(t *testing.T) {
	source := "TEXT splitfarreturn(SB),$0-0\n\tIRETL\n\tMOVL $1, AX\n\tRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"splitfarreturn": {Name: "splitfarreturn", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "anon_1:") || !strings.Contains(ir, "zext i32 1 to i64") {
		t.Fatalf("instruction after IRETL was not retained in its own block:\n%s", ir)
	}
}

func TestTranslateX86FarReturnCompleteGoAssemblerForms(t *testing.T) {
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
			forms := []struct {
				op  string
				arg string
			}{
				{op: "IRETW"},
				{op: "IRETL"},
				{op: "RETFW"},
				{op: "RETFW", arg: "$4"},
				{op: "RETFL"},
				{op: "RETFL", arg: "$4294967295"},
			}
			if target.goarch == "386" {
				forms = append(forms, struct {
					op  string
					arg string
				}{op: "RETFL", arg: "$4294967296"})
			} else {
				forms = append(forms,
					struct {
						op  string
						arg string
					}{op: "IRETQ"},
					struct {
						op  string
						arg string
					}{op: "RETFQ"},
					struct {
						op  string
						arg string
					}{op: "RETFQ", arg: "$4294967295"},
				)
			}
			var source strings.Builder
			sigs := make(map[string]FuncSig, len(forms))
			for index, form := range forms {
				name := fmt.Sprintf("farreturnform%d", index)
				fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n\t%s", name, form.op)
				if form.arg != "" {
					fmt.Fprintf(&source, " %s", form.arg)
				}
				source.WriteByte('\n')
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`.byte 0x66, 0xcf`,
				`.byte 0xcf`,
				`.byte 0x66, 0xcb`,
				`.byte 0x66, 0xca, 0x04, 0x00`,
				`.byte 0xcb`,
				`.byte 0xca, 0xff, 0xff`,
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			if target.goarch == "386" {
				if !strings.Contains(ir, `.byte 0xca, 0x00, 0x00`) {
					t.Errorf("386 IR is missing truncated Yi32 compatibility encoding:\n%s", ir)
				}
			} else {
				for _, want := range []string{`.byte 0x48, 0xcf`, `.byte 0x48, 0xcb`, `.byte 0x48, 0xca, 0xff, 0xff`} {
					if !strings.Contains(ir, want) {
						t.Errorf("amd64 IR is missing %s:\n%s", want, ir)
					}
				}
			}
			if got := strings.Count(ir, "unreachable"); got != len(forms) {
				t.Errorf("unreachable count = %d, want %d", got, len(forms))
			}
			compileLLVMToObject(t, llc, target.triple, "far-return-"+target.name+".ll", "far-return-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FarReturnRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "IRETW AX"},
		{goarch: "amd64", instruction: "IRETL.P"},
		{goarch: "amd64", instruction: "IRETQ $4"},
		{goarch: "amd64", instruction: "RETFW AX"},
		{goarch: "amd64", instruction: "RETFL $-2147483649"},
		{goarch: "amd64", instruction: "RETFQ $4294967296"},
		{goarch: "amd64", instruction: "RETFL $1, $2"},
		{goarch: "386", instruction: "IRETQ"},
		{goarch: "386", instruction: "RETFQ"},
		{goarch: "386", instruction: "RETFQ $4"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's far-return tables", test.instruction)
			}
		})
	}
}
