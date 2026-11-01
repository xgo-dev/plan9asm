package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func newARMCtxWithFuncForTest(t *testing.T, fn Func, sig FuncSig, sigs map[string]FuncSig) (*armCtx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]FuncSig{}
	}
	var b strings.Builder
	c := newARMCtx(&b, fn, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		t.Fatalf("emitEntryAllocasAndArgInit() error = %v", err)
	}
	return c, &b
}

func TestARMParserFlagAndHelperEdges(t *testing.T) {
	if !isSymbolicImmPlaceholder("$(16 + callbackArgs__size)") {
		t.Fatalf("isSymbolicImmPlaceholder() rejected symbolic immediate")
	}
	if isSymbolicImmPlaceholder("$123") {
		t.Fatalf("isSymbolicImmPlaceholder() accepted numeric immediate")
	}
	if base, sop, amt, shiftReg, ok := parseRegShift("R1@>R2"); !ok || base != "R1" || sop != ShiftRotate || shiftReg != "R2" || amt != 0 {
		t.Fatalf("parseRegShift(@>) = (%q, %q, %d, %q, %v)", base, sop, amt, shiftReg, ok)
	}
	if base, sop, amt, shiftReg, ok := parseRegShift("R3->1"); !ok || base != "R3" || sop != ShiftArith || shiftReg != "" || amt != 1 {
		t.Fatalf("parseRegShift(->) = (%q, %q, %d, %q, %v)", base, sop, amt, shiftReg, ok)
	}
	if regs, ok := expandRegRange("R7-R4"); !ok || len(regs) != 4 || regs[0] != "R7" || regs[3] != "R4" {
		t.Fatalf("expandRegRange(desc) = (%v, %v)", regs, ok)
	}
	if p, idx, suffix, ok := regRangeParts("F12"); !ok || p != "F" || idx != 12 || suffix != "" {
		t.Fatalf("regRangeParts(F12) = (%q, %d, %v)", p, idx, ok)
	}
	if _, _, _, ok := regRangeParts("SP"); ok {
		t.Fatalf("regRangeParts(SP) unexpectedly succeeded")
	}
	if got := absInt(-9); got != 9 {
		t.Fatalf("absInt(-9) = %d, want 9", got)
	}
	if op, err := parseOperand("$(16 + callbackArgs__size)"); err != nil || op.ImmRaw == "" {
		t.Fatalf("parseOperand(symbolic imm) = (%#v, %v)", op, err)
	}
	if op, err := parseOperand("[R0-R2,R4]"); err != nil || op.Kind != OpRegList || len(op.RegList) != 4 {
		t.Fatalf("parseOperand(reglist) = (%#v, %v)", op, err)
	}
	if op, err := parseOperand("R1<<R2"); err != nil || op.Kind != OpRegShift || op.ShiftReg != "R2" {
		t.Fatalf("parseOperand(regshift) = (%#v, %v)", op, err)
	}

	c, b := newARMCtxForTest(t, FuncSig{Name: "example.flags", Ret: Void}, nil)
	if err := c.storeFlagCond("", c.flagsZSlot, "true"); err != nil {
		t.Fatalf("storeFlagCond(empty) error = %v", err)
	}
	if err := c.storeFlagCond("AL", c.flagsNSlot, "false"); err != nil {
		t.Fatalf("storeFlagCond(AL) error = %v", err)
	}
	c.flagsWritten = true
	if err := c.storeFlagCond("EQ", c.flagsZSlot, "true"); err != nil {
		t.Fatalf("single-flag storeFlagCond(EQ) error = %v", err)
	}
	for _, cond := range []string{"EQ", "NE", "CS", "CC", "HI", "LS", "LT", "GE", "GT", "LE", "MI", "PL", "VS", "VC", "AL"} {
		if got, err := c.condValue(cond); err != nil || got == "" {
			t.Fatalf("condValue(%s) = (%q, %v)", cond, got, err)
		}
	}
	if err := c.setFlagsSub("EQ", "1", "2", "3"); err != nil {
		t.Fatalf("setFlagsSub() error = %v", err)
	}
	if err := c.setFlagsAdd("AL", "1", "2", "3"); err != nil {
		t.Fatalf("setFlagsAdd() error = %v", err)
	}
	if err := c.setFlagsLogic("EQ", "3"); err != nil {
		t.Fatalf("setFlagsLogic() error = %v", err)
	}
	c2, _ := newARMCtxForTest(t, FuncSig{Name: "example.flags2", Ret: Void}, nil)
	if _, err := c2.condValue("EQ"); err == nil {
		t.Fatalf("condValue(without flags) unexpectedly succeeded")
	}
	if _, err := c.condValue("NV"); err == nil {
		t.Fatalf("condValue(unsupported) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{"store i1 true", "select i1", "br i1", "icmp eq i1", "xor i1", "or i1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMAtomicMovmAndInstrEdges(t *testing.T) {
	c, b := newARMCtxWithFuncForTest(t, Func{
		Instrs: []Instr{
			{Op: "MOVD", Args: []Operand{{Kind: OpReg, Reg: "F0"}, {Kind: OpReg, Reg: "F1"}}},
		},
	}, FuncSig{Name: "example.helpers", Ret: Void}, nil)

	if ty, align, err := armAtomicType("LDREXB"); err != nil || ty != I8 || align != 1 {
		t.Fatalf("armAtomicType(LDREXB) = (%q, %d, %v)", ty, align, err)
	}
	if _, _, err := armAtomicType("BAD"); err == nil {
		t.Fatalf("armAtomicType(BAD) unexpectedly succeeded")
	}
	if got, err := c.atomicExtendToI32("%x", I8); err != nil || got == "" {
		t.Fatalf("atomicExtendToI32(I8) = (%q, %v)", got, err)
	}
	if _, err := c.atomicExtendToI32("%x", I64); err == nil {
		t.Fatalf("atomicExtendToI32(I64) unexpectedly succeeded")
	}
	if got, err := c.atomicTruncFromI32("%x", I8); err != nil || got == "" {
		t.Fatalf("atomicTruncFromI32(I8) = (%q, %v)", got, err)
	}
	if _, err := c.atomicTruncFromI32("%x", I64); err == nil {
		t.Fatalf("atomicTruncFromI32(I64) unexpectedly succeeded")
	}
	if ok, _, err := c.lowerAtomic("LDREX", Instr{Raw: "LDREX R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(LDREX invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerAtomic("STREX", Instr{Raw: "STREX R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(STREX invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerAtomic("STREXD", Instr{Raw: "STREXD R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(STREXD invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM", Instr{Raw: "MOVM R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); !ok || err == nil {
		t.Fatalf("lowerMOVM(invalid operands) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM", Instr{Raw: "MOVM (R1), [F0]", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R1"}}, {Kind: OpRegList, RegList: []Reg{"F0"}}}}); !ok || err == nil {
		t.Fatalf("lowerMOVM(non-gpr) = (%v, %v), want error", ok, err)
	}
	if ok, term, err := c.lowerData("MOVD", "", false, Instr{Raw: "MOVD F0, F1", Args: []Operand{{Kind: OpReg, Reg: "F0"}, {Kind: OpReg, Reg: "F1"}}}); !ok || term || err != nil {
		t.Fatalf("lowerData(MOVD freg->freg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerData("MOVD", "", false, Instr{Raw: "MOVD R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); !ok || err == nil {
		t.Fatalf("lowerData(MOVD invalid) = (%v, %v), want error", ok, err)
	}
	for _, ins := range []Instr{
		{Op: "MOVH", Raw: "MOVH R0, 2(R1)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpMem, Mem: MemRef{Base: "R1", Off: 2}}}},
		{Op: "MOVH", Raw: "MOVH R0, half<>(SB)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpSym, Sym: "half<>(SB)"}}},
	} {
		if ok, term, err := c.lowerData("MOVH", "", false, ins); !ok || term || err != nil {
			t.Fatalf("lowerData(%q) = (%v, %v, %v)", ins.Raw, ok, term, err)
		}
	}

	emitBr := func(string) {}
	emitCondBr := func(string, string, string) error { return nil }
	if term, err := c.lowerInstr(0, Instr{Op: "PCDATA", Raw: "PCDATA"}, emitBr, emitCondBr); term || err != nil {
		t.Fatalf("lowerInstr(PCDATA) = (%v, %v)", term, err)
	}
	if term, err := c.lowerInstr(0, Instr{Op: "UNDEF", Raw: "UNDEF"}, emitBr, emitCondBr); !term || err != nil {
		t.Fatalf("lowerInstr(UNDEF) = (%v, %v)", term, err)
	}
	if _, err := c.lowerInstr(0, Instr{Op: "UNKNOWN", Raw: "UNKNOWN"}, emitBr, emitCondBr); err == nil {
		t.Fatalf("lowerInstr(UNKNOWN) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{"store i64", `call void asm sideeffect "udf #0"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
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
			{Op: "MOVW", Raw: "MOVW missing+99(FP), R5", Args: []Operand{{Kind: OpFP, FPName: "missing", FPOffset: 99}, {Kind: OpReg, Reg: "R5"}}},
			{Op: "MOVW", Raw: "MOVW R5, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: "R5"}, {Kind: OpFP, FPName: "ret", FPOffset: 8}}},
			{Op: "MOVBU", Raw: "MOVBU R5, sink<>(SB)", Args: []Operand{{Kind: OpReg, Reg: "R5"}, {Kind: OpSym, Sym: "sink<>(SB)"}}},
			{Op: OpRET, Raw: "RET"},
		},
	}, FuncSig{
		Name: "linear_more",
		Ret:  I32,
		Frame: FrameLayout{
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

func TestARMBranchAndSyscallExtraEdges(t *testing.T) {
	c, _ := newARMCtxForTest(t, FuncSig{Name: "example.branch2", Ret: Void}, map[string]FuncSig{
		"example.argbad": {Name: "example.argbad", Args: []LLVMType{LLVMType("vec")}, Ret: Void},
	})
	c.blocks = []armBlock{{name: "entry"}}

	emitBr := func(string) {}
	emitCondBr := func(string, string, string) error { return nil }
	if ok, _, err := c.lowerBranch(0, "CALL", "EQ", Instr{Raw: "CALL.EQ R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL cond) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "CALL", "", Instr{Raw: "CALL", Args: nil}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL no args) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "CALL", "", Instr{Raw: "CALL $1", Args: []Operand{{Kind: OpImm, Imm: 1}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL bad target) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "B", "EQ", Instr{Raw: "B.EQ done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(B.EQ no fallthrough) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "BCC", "", Instr{Raw: "BCC done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(BCC no fallthrough) = (%v, %v), want error", ok, err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "argbad(SB)"}); err == nil {
		t.Fatalf("callSym(argbad) unexpectedly succeeded")
	}

	c2, b2 := newARMCtxForTest(t, FuncSig{Name: "example.sys", Ret: I32}, nil)
	delete(c2.regSlot, Reg("R4"))
	delete(c2.regSlot, Reg("R5"))
	if ok, _, err := c2.lowerSyscall("SWI", Instr{Raw: "SWI $0", Args: []Operand{{Kind: OpImm, Imm: 0}}}); !ok || err != nil {
		t.Fatalf("lowerSyscall(SWI $0) = (%v, %v)", ok, err)
	}
	out := b2.String()
	for _, want := range []string{"call i64 @syscall(", "zext i32 0 to i64", "store i32", "store i32 0, ptr %reg_R1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMBranchExactErrorCoverage(t *testing.T) {
	errTestSentinel := errors.New("sentinel")
	mk := func(ret LLVMType) *armCtx {
		c, _ := newARMCtxForTest(t, FuncSig{Name: "example.branch_exact", Ret: ret}, map[string]FuncSig{
			"example.voidsink": {Name: "example.voidsink", Ret: Void},
			"example.badarg":   {Name: "example.badarg", Args: []LLVMType{LLVMType("vec")}, Ret: Void},
		})
		c.blocks = []armBlock{{name: "entry"}, {name: "fall"}}
		return c
	}
	emitBr := func(string) {}
	errCond := func(string, string, string) error { return errTestSentinel }

	c := mk(Void)
	delete(c.regSlot, Reg("R0"))
	if _, _, err := c.lowerBranch(0, "CALL", "", Instr{Raw: "CALL R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(CALL reg load error) unexpectedly succeeded")
	}

	c = mk(Void)
	delete(c.regSlot, Reg("R1"))
	if _, _, err := c.lowerBranch(0, "CALL", "", Instr{Raw: "CALL (R1)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R1"}}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(CALL mem addr error) unexpectedly succeeded")
	}

	c = mk(Void)
	if _, _, err := c.lowerBranch(0, "B", "", Instr{Raw: "B", Args: nil}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B missing arg) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "EQ", Instr{Raw: "B.EQ R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B.EQ bad target) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "EQ", Instr{Raw: "B.EQ done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, errCond); err == nil {
		t.Fatalf("lowerBranch(B.EQ emit error) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "", Instr{Raw: "B $1", Args: []Operand{{Kind: OpImm, Imm: 1}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B bad target) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "BEQ", "", Instr{Raw: "BEQ", Args: nil}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(BEQ missing arg) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "BEQ", "", Instr{Raw: "BEQ R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(BEQ bad target) unexpectedly succeeded")
	}

	var got string
	condCapture := func(cond, _, _ string) error { got = cond; return errTestSentinel }
	if _, _, err := c.lowerBranch(0, "BCS", "", Instr{Raw: "BCS done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, condCapture); err == nil || got != "HS" {
		t.Fatalf("lowerBranch(BCS) = (%q, %v)", got, err)
	}
	got = ""
	if _, _, err := c.lowerBranch(0, "BCC", "", Instr{Raw: "BCC done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, condCapture); err == nil || got != "LO" {
		t.Fatalf("lowerBranch(BCC) = (%q, %v)", got, err)
	}

	c = mk(I32)
	if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "voidsink(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(void sink) error = %v", err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "missing(SB)"}); err != nil {
		t.Fatalf("callSym(missing sig) error = %v", err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "badarg(SB)"}); err == nil {
		t.Fatalf("callSym(bad arg type) unexpectedly succeeded")
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

func TestARMArithErrorCoverage(t *testing.T) {
	c, _ := newARMCtxForTest(t, FuncSig{Name: "example.arith_err", Ret: Void}, nil)
	if err := c.lowerARMALU("ADD", "", false, Instr{Raw: "ADD R0, $1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMALU(dst not reg 2-arg) unexpectedly succeeded")
	}
	if err := c.lowerARMALU("ADD", "", false, Instr{Raw: "ADD R0, R1, $2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpImm, Imm: 2}}}); err == nil {
		t.Fatalf("lowerARMALU(dst not reg 3-arg) unexpectedly succeeded")
	}
	if err := c.lowerARMALU("ADD", "", false, Instr{Raw: "ADD bad+8(FP), R0", Args: []Operand{{Kind: OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(src eval err) unexpectedly succeeded")
	}
	delete(c.regSlot, Reg("R0"))
	if err := c.lowerARMALU("ADD", "", false, Instr{Raw: "ADD $1, R0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(loadReg err) unexpectedly succeeded")
	}

	c, _ = newARMCtxForTest(t, FuncSig{Name: "example.arith_err2", Ret: Void}, nil)
	if err := c.lowerARMALU("RSB", "", true, Instr{Raw: "RSB.S $1, R0, R1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMALU(RSB.S) error = %v", err)
	}
	if err := c.lowerARMALU("ORR", "", true, Instr{Raw: "ORR.S R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err != nil {
		t.Fatalf("lowerARMALU(ORR.S) error = %v", err)
	}
	if err := c.lowerARMCompare("CMP", Instr{Raw: "CMP bad+8(FP), R0", Args: []Operand{{Kind: OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMCompare(src err) unexpectedly succeeded")
	}
	if err := c.lowerARMCompare("CMP", Instr{Raw: "CMP R0, bad+8(FP)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpFPAddr, FPName: "bad", FPOffset: 8}}}); err == nil {
		t.Fatalf("lowerARMCompare(lhs err) unexpectedly succeeded")
	}
	if err := c.lowerARMMVN("", false, Instr{Raw: "MVN", Args: nil}); err == nil {
		t.Fatalf("lowerARMMVN(len err) unexpectedly succeeded")
	}
	c3, _ := newARMCtxForTest(t, FuncSig{Name: "example.arith_err3", Ret: Void}, nil)
	if err := c3.lowerARMMVN("EQ", false, Instr{Raw: "MVN.EQ R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); err == nil {
		t.Fatalf("lowerARMMVN(select err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, Instr{Raw: "ADC", Args: nil}); err == nil {
		t.Fatalf("lowerARMADCSBC(len err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, Instr{Raw: "ADC bad+8(FP), R0", Args: []Operand{{Kind: OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(src err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, Instr{Raw: "ADC R0, bad+8(FP), R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: OpReg, Reg: "R1"}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(lhs err) unexpectedly succeeded")
	}

	c4, _ := newARMCtxForTest(t, FuncSig{Name: "example.pair_err", Ret: Void}, nil)
	delete(c4.regSlot, Reg("R1"))
	if err := c4.selectRegPairWrite("R1", "R2", "", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(store hi err) unexpectedly succeeded")
	}
	c5, _ := newARMCtxForTest(t, FuncSig{Name: "example.pair_err2", Ret: Void}, nil)
	if err := c5.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(cond err) unexpectedly succeeded")
	}
	c6, _ := newARMCtxForTest(t, FuncSig{Name: "example.pair_err3", Ret: Void}, nil)
	c6.flagsWritten = true
	delete(c6.regSlot, Reg("R1"))
	if err := c6.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(load hi err) unexpectedly succeeded")
	}
	c7, _ := newARMCtxForTest(t, FuncSig{Name: "example.pair_err4", Ret: Void}, nil)
	c7.flagsWritten = true
	delete(c7.regSlot, Reg("R2"))
	if err := c7.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(load lo err) unexpectedly succeeded")
	}
}
