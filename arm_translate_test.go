package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARMLinearAdd(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·Add(SB),NOSPLIT,$0-12
	MOVW	a+0(FP), R0
	MOVW	b+4(FP), R1
	ADD	R1, R0
	MOVW	R0, ret+8(FP)
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.Add": {
				Name: "example.Add",
				Args: []LLVMType{I32, I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1},
						{Offset: 4, Type: I32, Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 8, Type: I32, Index: 0, Field: -1},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{
		"target triple = \"armv7-unknown-linux-gnueabihf\"",
		"define i32 @example.Add(i32 %arg0, i32 %arg1)",
		"add i32",
		"ret i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMConditionalEffectsAndIndirectBranch(t *testing.T) {
	file, err := Parse(ArchARM, `TEXT ·caller(SB),NOSPLIT,$0-4
	MOVW p+0(FP), R7
	CMP $0, R0
	MOVW.EQ R0, (R7)
	MOVW.EQ R0, ·global(SB)
	BL.NE ·callee(SB)
	RET

TEXT ·callee(SB),NOSPLIT,$0-0
	RET

TEXT ·indirect(SB),NOSPLIT,$0-4
	MOVW target+0(FP), R11
	B (R11)

TEXT ·pcbranch(SB),NOSPLIT,$0-0
	CMP $0, R0
	BEQ 2(PC)
	MOVW $1, R0
	RET

TEXT ·spin(SB),NOSPLIT,$0-0
	JMP 0(PC)
`)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") }
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   resolve,
		Sigs: map[string]FuncSig{
			"example.caller":   {Name: "example.caller", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}},
			"example.callee":   {Name: "example.callee", Ret: Void},
			"example.indirect": {Name: "example.indirect", Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}},
			"example.pcbranch": {Name: "example.pcbranch", Ret: Void},
			"example.spin":     {Name: "example.spin", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"br i1",
		"store i32",
		`store i32 %`,
		`ptr @example.global`,
		`call void @example.callee()`,
		`mrs $0, apsr`,
		`call void asm sideeffect "bx $0"`,
		`define void @example.spin()`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMSystemRegisterMoves(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·systemregs(SB),NOSPLIT,$0-0
	MOVW $0,R0
	CMP R0,R0
	MOVW CPSR, R0
	MOVW R0, CPSR
	MOVW FPCR, R1
	MOVW R1, FPCR
	RET
`, map[string]FuncSig{"example.systemregs": {Name: "example.systemregs", Ret: Void}})
	for _, want := range []string{
		"mrs $0, cpsr",
		"msr cpsr_fs, $0",
		"vmrs $0, fpscr",
		"vmsr fpscr, $0",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
