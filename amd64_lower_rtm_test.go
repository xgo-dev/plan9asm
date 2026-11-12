package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestAMD64RTMGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64RTMSpec{
		"XBEGIN": {kind: amd64RTMBegin, operand: amd64RTMBranch, outputAX: true},
		"XABORT": {kind: amd64RTMAbort, operand: amd64RTMUnsignedByte},
		"XEND":   {kind: amd64RTMEnd},
		"XTEST":  {kind: amd64RTMTest},
	}
	if !reflect.DeepEqual(amd64RTMSpecs, want) {
		t.Fatalf("RTM grammar = %+v, want %+v", amd64RTMSpecs, want)
	}
}

func TestTranslateX86RTMCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT rtmforms(SB),$0-0
	XBEGIN fallback
	XTEST
	XEND
	RET
fallback:
	XABORT $0
	XABORT $255
	RET
TEXT rtmpcrel(SB),$0-0
	XBEGIN 2(PC)
	XEND
	RET
`
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"rtmforms": {Name: "rtmforms", Ret: Void},
					"rtmpcrel": {Name: "rtmpcrel", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+rtm"`,
				`call i32 @llvm.x86.xbegin()`,
				`call i32 @llvm.x86.xtest()`,
				`call void @llvm.x86.xend()`,
				`call void @llvm.x86.xabort(i8 0)`,
				`call void @llvm.x86.xabort(i8 -1)`,
				`icmp eq i32`,
				`store i1 %`,
				`br i1 %`,
			} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "rtm-"+target.name+".ll", "rtm-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86RTMRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "XBEGIN AX"},
		{goarch: "amd64", instruction: "XBEGIN (BX)"},
		{goarch: "amd64", instruction: "XABORT"},
		{goarch: "amd64", instruction: "XABORT $-1"},
		{goarch: "amd64", instruction: "XABORT $256"},
		{goarch: "amd64", instruction: "XABORT AX"},
		{goarch: "amd64", instruction: "XEND AX"},
		{goarch: "amd64", instruction: "XTEST.P"},
		{goarch: "386", instruction: "XABORT $256"},
		{goarch: "386", instruction: "XTEST AX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's RTM tables", test.instruction)
			}
		})
	}
}
