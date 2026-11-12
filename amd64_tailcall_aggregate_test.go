package plan9asm

import (
	"strings"
	"testing"
)

func TestAMD64TailCallAdaptsABIEquivalentAggregateReturns(t *testing.T) {
	tests := []struct {
		name      string
		callerRet LLVMType
		calleeRet LLVMType
		cast      string
	}{
		{
			name:      "integer slot to pointer slot",
			callerRet: LLVMType("{ i64, ptr }"),
			calleeRet: LLVMType("{ i64, i64 }"),
			cast:      "inttoptr i64",
		},
		{
			name:      "pointer slot to integer slot",
			callerRet: LLVMType("{ i64, i64 }"),
			calleeRet: LLVMType("{ i64, ptr }"),
			cast:      "ptrtoint ptr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := FuncSig{Name: "example.wrapper", Args: []LLVMType{Ptr}, Ret: tt.callerRet}
			callee := FuncSig{Name: "example.words", Args: []LLVMType{Ptr}, Ret: tt.calleeRet}
			c, b := newAMD64CtxWithFuncForTest(t, Func{}, caller, map[string]FuncSig{
				"example.words": callee,
			})

			if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "words(SB)"}); err != nil {
				t.Fatalf("tailCallAndRet() error = %v", err)
			}
			got := b.String()
			for _, want := range []string{
				"call " + string(tt.calleeRet) + " @\"example.words\"(ptr %arg0)",
				"extractvalue " + string(tt.calleeRet),
				tt.cast,
				"insertvalue " + string(tt.callerRet),
				"ret " + string(tt.callerRet),
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("tailCallAndRet() missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestAMD64TailCallRejectsABIIncompatibleAggregateReturns(t *testing.T) {
	tests := []struct {
		name      string
		callerRet LLVMType
		calleeRet LLVMType
	}{
		{name: "different field count", callerRet: LLVMType("{ i64, ptr }"), calleeRet: LLVMType("{ i64 }")},
		{name: "floating slot", callerRet: LLVMType("{ i64, ptr }"), calleeRet: LLVMType("{ i64, double }")},
		{name: "different integer width", callerRet: LLVMType("{ i64, ptr }"), calleeRet: LLVMType("{ i64, i32 }")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caller := FuncSig{Name: "example.wrapper", Args: []LLVMType{Ptr}, Ret: tt.callerRet}
			callee := FuncSig{Name: "example.words", Args: []LLVMType{Ptr}, Ret: tt.calleeRet}
			c, _ := newAMD64CtxWithFuncForTest(t, Func{}, caller, map[string]FuncSig{
				"example.words": callee,
			})

			if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "words(SB)"}); err == nil {
				t.Fatal("tailCallAndRet() unexpectedly accepted ABI-incompatible aggregate returns")
			}
		})
	}
}

func Test386TailCallAdaptsABIEquivalentAggregateReturns(t *testing.T) {
	caller := FuncSig{Name: "example.wrapper", Args: []LLVMType{Ptr}, Ret: LLVMType("{ i32, ptr }")}
	callee := FuncSig{Name: "example.words", Args: []LLVMType{Ptr}, Ret: LLVMType("{ i32, i32 }")}
	var b strings.Builder
	c := newX86Ctx(&b, Func{}, caller, testResolveSym("example"), map[string]FuncSig{
		"example.words": callee,
	}, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatalf("emitEntryAllocas() error = %v", err)
	}

	if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "words(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet() error = %v", err)
	}
	got := b.String()
	for _, want := range []string{
		"call { i32, i32 } @\"example.words\"(ptr %arg0)",
		"inttoptr i32",
		"insertvalue { i32, ptr }",
		"ret { i32, ptr }",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("tailCallAndRet() missing %q:\n%s", want, got)
		}
	}
}
