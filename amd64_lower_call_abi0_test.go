package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86ABI0CallUsesOutgoingStackFrame(t *testing.T) {
	for _, target := range []struct {
		goarch string
		triple string
		mov    string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", mov: "MOVQ"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", mov: "MOVL"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			source := "TEXT ·abi0Caller(SB),$48-0\n" +
				"\t" + target.mov + " $1, AX\n" +
				"\t" + target.mov + " AX, 0(SP)\n" +
				"\t" + target.mov + " $2, AX\n" +
				"\t" + target.mov + " AX, 8(SP)\n" +
				"\t" + target.mov + " $3, AX\n" +
				"\t" + target.mov + " AX, 16(SP)\n" +
				"\tMOVL $0x3fc00000, 24(SP)\n" +
				"\t" + target.mov + " $4, AX\n" +
				"\t" + target.mov + " AX, 32(SP)\n" +
				"\tCALL ·abi0Callee(SB)\n" +
				"\t" + target.mov + " 40(SP), AX\n" +
				"\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			word := I64
			if target.goarch == "386" {
				word = I32
			}
			aggregate := LLVMType("{ " + string(Ptr) + ", " + string(word) + ", " + string(word) + " }")
			callee := FuncSig{
				Name: "abi0Callee",
				Args: []LLVMType{aggregate, LLVMType("float"), LLVMType("double")},
				Ret:  word,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: 0},
						{Offset: 8, Type: word, Index: 0, Field: 1},
						{Offset: 16, Type: word, Index: 0, Field: 2},
						{Offset: 24, Type: LLVMType("float"), Index: 1, Field: -1},
						{Offset: 32, Type: LLVMType("double"), Index: 2, Field: -1},
					},
					Results: []FrameSlot{{Offset: 40, Type: word, Index: 0, Field: -1}},
				},
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"abi0Caller": {Name: "abi0Caller", Ret: Void},
					"abi0Callee": callee,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load ptr", "load float", "load double", "call " + string(word) + " @abi0Callee", "store " + string(word)} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ABI0 call omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "abi0-call-"+target.goarch+".ll", "abi0-call-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86IndirectBranchCompatibilitySyntax(t *testing.T) {
	const source = `
TEXT ·indirectCallRegister(SB),$0-0
	CALL *AX
	RET

TEXT ·indirectCallSymbol(SB),$0-0
	CALL *·pointer(SB)
	RET

TEXT ·indirectJumpRegister(SB),$0-0
	JMP *AX
`
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"indirectCallRegister": {Name: "indirectCallRegister", Ret: Void},
					"indirectCallSymbol":   {Name: "indirectCallSymbol", Ret: Void},
					"indirectJumpRegister": {Name: "indirectJumpRegister", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, "call i64 %"); got != 3 {
				t.Fatalf("indirect CALL/JMP count = %d, want 3:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "indirect-branch-"+target.goarch+".ll", "indirect-branch-"+target.goarch+".o", ll)
		})
	}
}
