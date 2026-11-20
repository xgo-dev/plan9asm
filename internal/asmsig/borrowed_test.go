package asmsig

import (
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestARM64BorrowedTailFrameRequiresCompleteImmediateStores(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caller string
		want   bool
	}{
		{name: "one word", caller: "MOVD R3, 8(RSP)\nB helper(SB)", want: true},
		{name: "zero offset target", caller: "MOVD R3, 8(RSP)\nB helper+0(SB)", want: true},
		{name: "two words", caller: "MOVD R3, 16(RSP)\nMOVD R4, 8(RSP)\nB helper(SB)", want: true},
		{name: "missing store", caller: "B helper(SB)"},
		{name: "wrong slot", caller: "MOVD R3, 24(RSP)\nB helper(SB)"},
		{name: "intervening instruction", caller: "MOVD R3, 8(RSP)\nADD $1, R3\nB helper(SB)"},
		{name: "ordinary call", caller: "MOVD R3, 8(RSP)\nBL helper(SB)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := []plan9asm.FrameSlot{{Offset: 0, Type: plan9asm.I64, Index: 0}}
			args := []plan9asm.LLVMType{plan9asm.I64}
			if tc.name == "two words" {
				params = append(params, plan9asm.FrameSlot{Offset: 8, Type: plan9asm.I64, Index: 1})
				args = append(args, plan9asm.I64)
			}
			file, err := plan9asm.Parse(plan9asm.ArchARM64,
				"TEXT caller(SB),$0\n"+tc.caller+"\nTEXT helper(SB),$0\nMOVD vector+0(FP), R3\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			declared := plan9asm.FuncSig{Name: "helper", Ret: plan9asm.Void}
			inferred := plan9asm.FuncSig{
				Name: "helper", Args: args, Ret: plan9asm.Void,
				Frame: plan9asm.FrameLayout{Params: params},
			}
			got, ok := ARM64BorrowedTailFrame(file, file.Funcs[1], declared, inferred, func(s string) string { return s })
			if ok != tc.want {
				t.Fatalf("borrowed tail frame accepted=%t, want %t", ok, tc.want)
			}
			if ok && (len(got.Args) != len(args) || len(got.Frame.Params) != len(params)) {
				t.Fatalf("incomplete borrowed frame: %+v", got)
			}
		})
	}
}

func TestARM64BorrowedTailFrameRejectsUnprovenSecondEntry(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM64, `TEXT first(SB),$0
	MOVD R3, 8(RSP)
	B helper(SB)
TEXT second(SB),$0
	B helper(SB)
TEXT helper(SB),$0
	MOVD vector+0(FP), R3
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	declared := plan9asm.FuncSig{Name: "helper", Ret: plan9asm.Void}
	inferred := plan9asm.FuncSig{
		Name: "helper", Args: []plan9asm.LLVMType{plan9asm.I64}, Ret: plan9asm.Void,
		Frame: plan9asm.FrameLayout{Params: []plan9asm.FrameSlot{{Type: plan9asm.I64}}},
	}
	if _, ok := ARM64BorrowedTailFrame(file, file.Funcs[2], declared, inferred, func(s string) string { return s }); ok {
		t.Fatal("accepted a helper with an unproven second entry")
	}
}

func TestARM64BorrowedTailFrameRejectsConflictingDeclarations(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM64,
		"TEXT caller(SB),$0\nMOVD R3, 8(RSP)\nB helper(SB)\nTEXT helper(SB),$0\nMOVD vector+0(FP), R3\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	inferred := plan9asm.FuncSig{
		Name: "helper", Args: []plan9asm.LLVMType{plan9asm.I64}, Ret: plan9asm.Void,
		Frame: plan9asm.FrameLayout{Params: []plan9asm.FrameSlot{{Type: plan9asm.I64}}},
	}
	for _, declared := range []plan9asm.FuncSig{
		{Name: "helper", Args: []plan9asm.LLVMType{plan9asm.I64}, Ret: plan9asm.Void},
		{Name: "helper", Ret: plan9asm.I64},
	} {
		if _, ok := ARM64BorrowedTailFrame(file, file.Funcs[1], declared, inferred, func(s string) string { return s }); ok {
			t.Fatalf("accepted conflicting Go declaration: %+v", declared)
		}
	}
}
