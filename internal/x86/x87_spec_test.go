package x86

import (
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestX87SpecCoversAllX87Ops(t *testing.T) {
	// Verify all 7 x87 constants live in the single shared x87ConstSpecs map.
	wantConsts := []asm.Op{"FLD1", "FLDZ", "FLDPI", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2"}
	for _, op := range wantConsts {
		if _, ok := x87ConstSpecs[op]; !ok {
			t.Fatalf("missing x87 constant %s in shared x87ConstSpecs", op)
		}
		if cat := classifyX87Op(op); cat != x87CatConst {
			t.Fatalf("classifyX87Op(%s) = %v, want x87CatConst", op, cat)
		}
	}
	if len(x87ConstSpecs) != len(wantConsts) {
		t.Fatalf("x87ConstSpecs has %d entries, want %d", len(x87ConstSpecs), len(wantConsts))
	}

	// Verify shared FMOVD / FMOVDP stack classification matches Go's asm6.go encoding.
	f0 := asm.Operand{Kind: asm.OpReg, Reg: "F0"}
	f1 := asm.Operand{Kind: asm.OpReg, Reg: "F1"}
	mem := asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.SP, Off: 0}}

	moveCases := []struct {
		name     string
		op       asm.Op
		args     []asm.Operand
		wantKind x87MoveKind
		wantPop  bool
	}{
		{"FMOVD F1, F0 pushes ST(1)", "FMOVD", []asm.Operand{f1, f0}, x87MovePushReg, false},
		{"FMOVD F0, F0 pushes ST(0)", "FMOVD", []asm.Operand{f0, f0}, x87MovePushReg, false},
		{"FMOVD F0, F1 overwrites ST(1)", "FMOVD", []asm.Operand{f0, f1}, x87MoveStoreReg, false},
		{"FMOVD mem, F0 pushes mem", "FMOVD", []asm.Operand{mem, f0}, x87MovePushMem, false},
		{"FMOVD F0, mem stores without pop", "FMOVD", []asm.Operand{f0, mem}, x87MoveStoreMem, false},
		{"FMOVDP F0, F1 stores ST(1) then pops", "FMOVDP", []asm.Operand{f0, f1}, x87MoveStorePopReg, true},
		{"FMOVDP F0, F0 pops ST(0)", "FMOVDP", []asm.Operand{f0, f0}, x87MoveStorePopReg, true},
		{"FMOVDP F0, mem stores then pops", "FMOVDP", []asm.Operand{f0, mem}, x87MoveStorePopMem, true},
		{"FMOVB mem, F0 pushes 10-byte BCD", "FMOVB", []asm.Operand{mem, f0}, x87MovePushMem, false},
		{"FMOVBP F0, mem stores 10-byte BCD + pops", "FMOVBP", []asm.Operand{f0, mem}, x87MoveStorePopMem, true},
		{"FBLD mem pushes 10-byte BCD", "FBLD", []asm.Operand{mem}, x87MovePushMem, false},
		{"FBSTP mem stores 10-byte BCD + pops", "FBSTP", []asm.Operand{mem}, x87MoveStorePopMem, true},
	}
	for _, tc := range moveCases {
		plan := classifyX87Move(tc.op, tc.args)
		if plan.Kind != tc.wantKind || plan.Pop != tc.wantPop {
			t.Fatalf("%s: classifyX87Move(%s) = {Kind:%v Pop:%v}, want {Kind:%v Pop:%v}",
				tc.name, tc.op, plan.Kind, plan.Pop, tc.wantKind, tc.wantPop)
		}
	}
}
