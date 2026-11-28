package plan9asm

import (
	"strings"
	"testing"
)

func TestValidateResolvedImmediates(t *testing.T) {
	fn := Func{Instrs: []Instr{{Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}}}}}
	if err := validateResolvedImmediates(ArchAMD64, fn); err != nil {
		t.Fatalf("validateResolvedImmediates(amd64) error = %v", err)
	}
	if err := validateResolvedImmediates(ArchARM, fn); err == nil {
		t.Fatalf("validateResolvedImmediates(arm) unexpectedly succeeded")
	}
}

func TestTranslateFuncLinearEdgeCases(t *testing.T) {
	var b strings.Builder
	err := translateFuncLinear(&b, ArchARM, Func{
		Sym: "linear_err",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW $(bad), R0", Args: []Operand{{Kind: OpImm, ImmRaw: "$(bad)"}, {Kind: OpReg, Reg: "R0"}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{Name: "linear_err", Ret: I32}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(unresolved imm) unexpectedly succeeded")
	}

	b.Reset()
	err = translateFuncLinear(&b, ArchAMD64, Func{
		Sym: "linear_shift",
		Instrs: []Instr{
			{Op: "MOVQ", Raw: "MOVQ AX<<1, AX", Args: []Operand{{Kind: OpRegShift, Reg: AX, ShiftOp: ShiftLeft, ShiftAmount: 1}, {Kind: OpReg, Reg: AX}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{Name: "linear_shift", Ret: I64}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(non-arm shift) unexpectedly succeeded")
	}

	b.Reset()
	err = translateFuncLinear(&b, ArchARM, Func{
		Sym: "linear_bad_add",
		Instrs: []Instr{
			{Op: "ADD", Raw: "ADD R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{Name: "linear_bad_add", Ret: I32}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(bad add) unexpectedly succeeded")
	}
}

func TestTranslateFuncLinearAdditionalPaths(t *testing.T) {
	var b strings.Builder
	err := translateFuncLinear(&b, ArchARM, Func{
		Sym: "linear_more",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW 8(R1)(R2*4), R3", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R1", Index: "R2", Scale: 4, Off: 8}}, {Kind: OpReg, Reg: "R3"}}},
			{Op: "MOVW", Raw: "MOVW $runtime·main(SB), R4", Args: []Operand{{Kind: OpSym, Sym: "$runtime·main(SB)"}, {Kind: OpReg, Reg: "R4"}}},
			{Op: "MOVW", Raw: "MOVW val+0(FP), R5", Args: []Operand{{Kind: OpFP, FPName: "val", FPOffset: 0}, {Kind: OpReg, Reg: "R5"}}},
			{Op: "MOVW", Raw: "MOVW R5, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: "R5"}, {Kind: OpFP, FPName: "ret", FPOffset: 8}}},
			{Op: "MOVBU", Raw: "MOVBU R5, sink<>(SB)", Args: []Operand{{Kind: OpReg, Reg: "R5"}, {Kind: OpSym, Sym: "sink<>(SB)"}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{
		Name: "linear_more",
		Args: []LLVMType{I32},
		Ret:  I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0}},
		},
	}, false)
	if err != nil {
		t.Fatalf("translateFuncLinear(extra paths) error = %v", err)
	}
	out := b.String()
	for _, want := range []string{
		"mul i64",
		"inttoptr i64",
		"load i64, ptr",
		"trunc i64 0 to i32",
		"ret i32",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestTranslateFuncLinearMissedBranches(t *testing.T) {
	var b strings.Builder

	file, err := Parse(ArchARM, `TEXT ·cfgbad(SB),NOSPLIT,$0-0
	CMP R0, R0
	BAD
	RET
`)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(sym string) string { return "example." + strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"example.cfgbad": {Name: "example.cfgbad", Ret: Void},
		},
	})
	if err == nil {
		t.Fatalf("Translate(cfgbad) unexpectedly succeeded")
	}

	err = translateFuncLinear(&b, ArchARM, Func{
		Sym: "shift_ok",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW R1>>1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftRight, ShiftAmount: 1}, {Kind: OpReg, Reg: "R0"}}},
			{Op: "MOVW", Raw: "MOVW R0->1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftArith, ShiftAmount: 1}, {Kind: OpReg, Reg: "R0"}}},
			{Op: "MOVW", Raw: "MOVW R0@>1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftRotate, ShiftAmount: 1}, {Kind: OpReg, Reg: "R0"}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{Name: "shift_ok", Ret: I32}, false)
	if err != nil {
		t.Fatalf("translateFuncLinear(shift ok) error = %v", err)
	}

	b.Reset()
	err = translateFuncLinear(&b, ArchARM, Func{
		Sym: "shift_bad_base",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW R0<<1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftLeft, ShiftAmount: 1}, {Kind: OpReg, Reg: "R0"}}},
		},
	}, FuncSig{Name: "shift_bad_base", Args: []LLVMType{LLVMType("{ i32, i32 }")}, ArgRegs: []Reg{"R0"}, Ret: I32}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(shift bad base) unexpectedly succeeded")
	}

	b.Reset()
	err = translateFuncLinear(&b, ArchARM, Func{
		Sym: "shift_bad_reg",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW R0<<R1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftLeft, ShiftReg: "R1"}, {Kind: OpReg, Reg: "R0"}}},
		},
	}, FuncSig{Name: "shift_bad_reg", Args: []LLVMType{I32, LLVMType("{ i32, i32 }")}, ArgRegs: []Reg{"R0", "R1"}, Ret: I32}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(shift bad reg) unexpectedly succeeded")
	}

	b.Reset()
	err = translateFuncLinear(&b, ArchARM, Func{
		Sym: "shift_bad_op",
		Instrs: []Instr{
			{Op: "MOVW", Raw: "MOVW R0**1, R0", Args: []Operand{{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftOp("**"), ShiftAmount: 1}, {Kind: OpReg, Reg: "R0"}}},
		},
	}, FuncSig{Name: "shift_bad_op", Ret: I32}, false)
	if err == nil {
		t.Fatalf("translateFuncLinear(shift bad op) unexpectedly succeeded")
	}

	for _, tc := range []struct {
		arch Arch
		op   Instr
	}{
		{arch: ArchAMD64, op: Instr{Op: "MOVW", Raw: "MOVW AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}}},
		{arch: ArchAMD64, op: Instr{Op: "MOVBU", Raw: "MOVBU AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}}},
		{arch: ArchAMD64, op: Instr{Op: "ADD", Raw: "ADD AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}}},
	} {
		b.Reset()
		if err := translateFuncLinear(&b, tc.arch, Func{Sym: "skip", Instrs: []Instr{tc.op, {Op: OpRET, Raw: "RET"}}}, FuncSig{Name: "skip", Ret: I64}, false); err != nil {
			t.Fatalf("translateFuncLinear(skip %s) error = %v", tc.op.Op, err)
		}
	}

	for _, tc := range []Instr{
		{Op: "MOVW", Raw: "MOVW R0, sink<>(SB)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpSym, Sym: "sink<>(SB)"}}},
		{Op: "MOVBU", Raw: "MOVBU R0, sink<>(SB)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpSym, Sym: "sink<>(SB)"}}},
		{Op: "ADD", Raw: "ADD R0, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpFP, FPName: "ret", FPOffset: 8}}},
	} {
		b.Reset()
		err := translateFuncLinear(&b, ArchARM, Func{Sym: "skip2", Instrs: []Instr{tc, {Op: OpRET, Raw: "RET"}}}, FuncSig{
			Name: "skip2",
			Ret:  I32,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0}},
			},
		}, false)
		if err == nil && tc.Op == "ADD" {
			t.Fatalf("translateFuncLinear(bad add dst) unexpectedly succeeded")
		}
		if err != nil && tc.Op != "ADD" {
			t.Fatalf("translateFuncLinear(skip arm %s) error = %v", tc.Op, err)
		}
	}
}
