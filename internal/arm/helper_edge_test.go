package arm

import (
	"errors"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	"testing"
)

func newARMCtxWithFuncForTest(t *testing.T, fn asm.Func, sig asm.FuncSig, sigs map[string]asm.FuncSig) (*armCtx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]asm.FuncSig{}
	}
	var b strings.Builder
	c := newARMCtx(&b, fn, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		t.Fatalf("emitEntryAllocasAndArgInit() error = %v", err)
	}
	return c, &b
}

func testResolveSym(pkg string) func(string) string {
	return func(sym string) string {
		sym = strings.ReplaceAll(sym, "∕", "/")
		sym = strings.TrimSuffix(sym, "<>")
		if strings.HasPrefix(sym, "·") {
			return pkg + "." + strings.TrimPrefix(sym, "·")
		}
		if strings.Contains(sym, "·") {
			return strings.ReplaceAll(sym, "·", ".")
		}
		if !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
			return pkg + "." + sym
		}
		return sym
	}
}

func newARMCtxForTest(t *testing.T, sig asm.FuncSig, sigs map[string]asm.FuncSig) (*armCtx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]asm.FuncSig{}
	}
	var b strings.Builder
	c := newARMCtx(&b, asm.Func{}, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		t.Fatalf("emitEntryAllocasAndArgInit() error = %v", err)
	}
	return c, &b
}

func TestARMHelperCoverage(t *testing.T) {
	t.Run("DecodeAndValidate", func(t *testing.T) {
		cases := []struct {
			raw       string
			wantMode  string
			wantWrite bool
		}{
			{raw: "MOVM.IA.W", wantMode: "IA", wantWrite: true},
			{raw: "MOVM.DBW", wantMode: "DB", wantWrite: true},
			{raw: "MOVM.WP", wantMode: "DB", wantWrite: true},
			{raw: "MOVM.IB", wantMode: "IB", wantWrite: false},
			{raw: "MOVM.DA", wantMode: "DA", wantWrite: false},
			{raw: "MOVM", wantMode: "IA", wantWrite: false},
		}
		for _, tc := range cases {
			mode, writeback := armDecodeMOVM(tc.raw)
			if mode != tc.wantMode || writeback != tc.wantWrite {
				t.Fatalf("armDecodeMOVM(%q) = (%q, %v), want (%q, %v)", tc.raw, mode, writeback, tc.wantMode, tc.wantWrite)
			}
		}
		if !armRegListAllGPR([]asm.Reg{"R0", "R7", "R15"}) {
			t.Fatalf("armRegListAllGPR() rejected general-purpose list")
		}
		if armRegListAllGPR([]asm.Reg{"R0", "F0"}) {
			t.Fatalf("armRegListAllGPR() accepted mixed register list")
		}

		if got, ok := armBranchTarget(asm.Operand{Kind: asm.OpIdent, Ident: "loop"}); !ok || got != "loop" {
			t.Fatalf("armBranchTarget(ident) = (%q, %v)", got, ok)
		}
		if got, ok := armBranchTarget(asm.Operand{Kind: asm.OpSym, Sym: "helper<>(SB)"}); !ok || got != "helper" {
			t.Fatalf("armBranchTarget(sym) = (%q, %v)", got, ok)
		}
		if _, ok := armBranchTarget(asm.Operand{Kind: asm.OpReg, Reg: "R0"}); ok {
			t.Fatalf("armBranchTarget(reg) unexpectedly succeeded")
		}

		base, cond, postInc, setFlags := armDecodeOp("ADD.EQ.S.P")
		if base != "ADD" || cond != "EQ" || !postInc || !setFlags {
			t.Fatalf("armDecodeOp() = (%q, %q, %v, %v)", base, cond, postInc, setFlags)
		}

		if got, err := armNextReg("R7"); err != nil || got != "R8" {
			t.Fatalf("armNextReg(R7) = (%q, %v), want (R8, nil)", got, err)
		}
		if _, err := armNextReg("R15"); err == nil {
			t.Fatalf("armNextReg(R15) unexpectedly succeeded")
		}
		if _, err := armNextReg("F0"); err == nil {
			t.Fatalf("armNextReg(F0) unexpectedly succeeded")
		}

		if got, ok := asm.ParseReg("W3"); !ok || got != "R3" {
			t.Fatalf("parseReg(W3) = (%q, %v)", got, ok)
		}
		if got, ok := asm.ParseReg("LR"); !ok || got != "R30" {
			t.Fatalf("parseReg(LR) = (%q, %v)", got, ok)
		}
		if got, ok := asm.ParseReg("G"); !ok || got != "R28" {
			t.Fatalf("parseReg(G) = (%q, %v)", got, ok)
		}
		if got := (asm.Operand{Kind: asm.OpImm, ImmRaw: "$(a+b)"}).String(); got != "$(a+b)" {
			t.Fatalf("Operand.String() = %q, want unresolved symbolic immediate", got)
		}
	})

	t.Run("CtxRetAndStore", func(t *testing.T) {
		c, b := newARMCtxForTest(t, asm.FuncSig{
			Name: "example.f",
			Ret:  asm.I16,
			Frame: asm.FrameLayout{
				Results: []asm.FrameSlot{{Offset: 8, Type: asm.I16, Index: 0}},
			},
		}, nil)
		c.flagsWritten = true

		if err := c.selectRegWrite("R1", "EQ", "7"); err != nil {
			t.Fatalf("selectRegWrite(EQ) error = %v", err)
		}
		if err := c.selectRegWrite("R2", "AL", "9"); err != nil {
			t.Fatalf("selectRegWrite(AL) error = %v", err)
		}
		if err := c.storeARMValue(asm.Operand{Kind: asm.OpFP, FPOffset: 8}, "42", 32, "", false, "MOVW R0, ret+8(FP)"); err != nil {
			t.Fatalf("storeARMValue(FP) error = %v", err)
		}
		if err := c.storeARMValue(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R3", Off: 4}}, "55", 8, "", false, "MOVB R0, 4(R3)"); err != nil {
			t.Fatalf("storeARMValue(mem) error = %v", err)
		}
		if err := c.storeARMValue(asm.Operand{Kind: asm.OpSym, Sym: "global<>(SB)"}, "1", 32, "", false, "MOVW R0, global<>(SB)"); err != nil {
			t.Fatalf("storeARMValue(sym) error = %v", err)
		}
		if err := c.storeARMValue(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R3"}}, "1", 32, "EQ", false, "MOVW.EQ R0, (R3)"); err == nil {
			t.Fatalf("storeARMValue(cond mem) unexpectedly succeeded")
		}
		if err := c.storeARMValue(asm.Operand{Kind: asm.OpIdent, Ident: "bad"}, "1", 32, "", false, "bad"); err == nil {
			t.Fatalf("storeARMValue(invalid) unexpectedly succeeded")
		}
		if got, err := c.ptrFromSB("$runtime·main+8(SB)"); err != nil || got == "" {
			t.Fatalf("ptrFromSB() = (%q, %v)", got, err)
		}
		if got, err := c.loadRetSlotFallback(asm.FrameSlot{Type: asm.Ptr}); err != nil || got == "" {
			t.Fatalf("loadRetSlotFallback(ptr) = (%q, %v)", got, err)
		}
		if got, err := c.loadRetSlotFallback(asm.FrameSlot{Type: asm.I64}); err != nil || got == "" {
			t.Fatalf("loadRetSlotFallback(i64) = (%q, %v)", got, err)
		}
		if _, err := c.loadRetSlotFallback(asm.FrameSlot{Type: asm.LLVMType("v4i32")}); err == nil {
			t.Fatalf("loadRetSlotFallback(invalid) unexpectedly succeeded")
		}
		c.lowerRetZero()

		out := b.String()
		for _, want := range []string{
			"select i1",
			"trunc i32 42 to i16",
			"store i8",
			`store i32 1, ptr @"example.global"`,
			`getelementptr i8, ptr @"runtime.main", i32 8`,
			"inttoptr i32",
			"zext i32",
			"ret i16 0",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("BranchCallAndCastPaths", func(t *testing.T) {
		sigs := map[string]asm.FuncSig{
			"example.retBool": {Name: "example.retBool", Ret: asm.I1},
			"example.retPtr":  {Name: "example.retPtr", Ret: asm.Ptr},
			"example.ret64":   {Name: "example.ret64", Ret: asm.I64},
			"example.sink": {
				Name:    "example.sink",
				Args:    []asm.LLVMType{asm.I1, asm.I8, asm.I16, asm.I32, asm.Ptr, asm.I64},
				ArgRegs: []asm.Reg{"R0", "R1", "R2", "R3", "R4", "R5"},
				Ret:     asm.Void,
			},
		}
		c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.caller", Ret: asm.Void}, sigs)

		if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "retBool(SB)"}); err != nil {
			t.Fatalf("callSym(retBool) error = %v", err)
		}
		if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "retPtr(SB)"}); err != nil {
			t.Fatalf("callSym(retPtr) error = %v", err)
		}
		if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "ret64(SB)"}); err != nil {
			t.Fatalf("callSym(ret64) error = %v", err)
		}
		if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "runtime·entersyscall(SB)"}); err != nil {
			t.Fatalf("callSym(runtime·entersyscall) error = %v", err)
		}
		if err := c.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "sink(SB)"}); err != nil {
			t.Fatalf("tailCallAndRet() error = %v", err)
		}

		emitBr := func(string) {}
		emitCondBr := func(string, string, string) error { return nil }
		if ok, term, err := c.lowerBranch(0, "CALL", "", asm.Instr{
			Raw:  "CALL R1",
			Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R1"}},
		}, emitBr, emitCondBr); !ok || term || err != nil {
			t.Fatalf("lowerBranch(CALL reg) = (%v, %v, %v)", ok, term, err)
		}
		if ok, term, err := c.lowerBranch(0, "BL", "", asm.Instr{
			Raw:  "BL (R1)",
			Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R1"}}},
		}, emitBr, emitCondBr); !ok || term || err != nil {
			t.Fatalf("lowerBranch(BL mem) = (%v, %v, %v)", ok, term, err)
		}

		out := b.String()
		for _, want := range []string{
			"zext i1",
			"ptrtoint ptr",
			"trunc i64",
			`call void @"example.sink"(`,
			"ret void",
			"asm sideeffect \"blx $0\"",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("ARMValueAsI32AndLowerRetZeroVariants", func(t *testing.T) {
		tests := []struct {
			ret  asm.LLVMType
			want string
		}{
			{ret: asm.Void, want: "ret void"},
			{ret: asm.I1, want: "ret i1 false"},
			{ret: asm.Ptr, want: "ret ptr null"},
			{ret: asm.I32, want: "ret i32 0"},
		}
		for _, tc := range tests {
			c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.retzero", Ret: tc.ret}, nil)
			c.lowerRetZero()
			if !strings.Contains(b.String(), tc.want) {
				t.Fatalf("lowerRetZero(%s) missing %q in:\n%s", tc.ret, tc.want, b.String())
			}
		}

		c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.cast", Ret: asm.Void}, nil)
		for _, ty := range []asm.LLVMType{asm.Ptr, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64} {
			if got, ok, err := armValueAsI32(c, ty, "%v"); err != nil || !ok || got == "" {
				t.Fatalf("armValueAsI32(%s) = (%q, %v, %v)", ty, got, ok, err)
			}
		}
		if _, ok, err := armValueAsI32(c, asm.LLVMType("v2i32"), "%v"); err != nil || ok {
			t.Fatalf("armValueAsI32(unsupported) = (_, %v, %v), want (_, false, nil)", ok, err)
		}
		out := b.String()
		for _, want := range []string{"ptrtoint ptr %v to i32", "zext i1 %v to i32", "trunc i64 %v to i32"} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in output:\n%s", want, out)
			}
		}
	})
}

func TestARMParserFlagAndHelperEdges(t *testing.T) {
	if !asm.IsSymbolicImmPlaceholder("$(16 + callbackArgs__size)") {
		t.Fatalf("IsSymbolicImmPlaceholder() rejected symbolic immediate")
	}
	if asm.IsSymbolicImmPlaceholder("$123") {
		t.Fatalf("IsSymbolicImmPlaceholder() accepted numeric immediate")
	}
	if base, sop, amt, shiftReg, ok := asm.ParseRegShift("R1@>R2"); !ok || base != "R1" || sop != asm.ShiftRotate || shiftReg != "R2" || amt != 0 {
		t.Fatalf("ParseRegShift(@>) = (%q, %q, %d, %q, %v)", base, sop, amt, shiftReg, ok)
	}
	if base, sop, amt, shiftReg, ok := asm.ParseRegShift("R3->1"); !ok || base != "R3" || sop != asm.ShiftArith || shiftReg != "" || amt != 1 {
		t.Fatalf("ParseRegShift(->) = (%q, %q, %d, %q, %v)", base, sop, amt, shiftReg, ok)
	}
	if regs, ok := asm.ExpandRegRange("R7-R4"); !ok || len(regs) != 4 || regs[0] != "R7" || regs[3] != "R4" {
		t.Fatalf("ExpandRegRange(desc) = (%v, %v)", regs, ok)
	}
	if p, idx, suffix, ok := asm.RegRangeParts("F12"); !ok || p != "F" || idx != 12 || suffix != "" {
		t.Fatalf("RegRangeParts(F12) = (%q, %d, %v)", p, idx, ok)
	}
	if _, _, _, ok := asm.RegRangeParts("SP"); ok {
		t.Fatalf("RegRangeParts(SP) unexpectedly succeeded")
	}
	if op, err := asm.ParseOperand("$(16 + callbackArgs__size)"); err != nil || op.ImmRaw == "" {
		t.Fatalf("parseOperand(symbolic imm) = (%#v, %v)", op, err)
	}
	if op, err := asm.ParseOperand("[R0-R2,R4]"); err != nil || op.Kind != asm.OpRegList || len(op.RegList) != 4 {
		t.Fatalf("parseOperand(reglist) = (%#v, %v)", op, err)
	}
	if op, err := asm.ParseOperand("R1<<R2"); err != nil || op.Kind != asm.OpRegShift || op.ShiftReg != "R2" {
		t.Fatalf("parseOperand(regshift) = (%#v, %v)", op, err)
	}

	c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.flags", Ret: asm.Void}, nil)
	if err := c.storeFlagCond("", c.flagsZSlot, "true"); err != nil {
		t.Fatalf("storeFlagCond(empty) error = %v", err)
	}
	if err := c.storeFlagCond("AL", c.flagsNSlot, "false"); err != nil {
		t.Fatalf("storeFlagCond(AL) error = %v", err)
	}
	c.flagsWritten = true
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
	c2, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.flags2", Ret: asm.Void}, nil)
	if _, err := c2.condValue("EQ"); err == nil {
		t.Fatalf("condValue(without flags) unexpectedly succeeded")
	}
	if _, err := c.condValue("NV"); err == nil {
		t.Fatalf("condValue(unsupported) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{"store i1 true", "select i1", "icmp eq i1", "xor i1", "or i1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMAtomicMovmAndInstrEdges(t *testing.T) {
	c, b := newARMCtxWithFuncForTest(t, asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, {Kind: asm.OpReg, Reg: "F1"}}},
		},
	}, asm.FuncSig{Name: "example.helpers", Ret: asm.Void}, nil)

	if ty, align, err := armAtomicType("LDREXB"); err != nil || ty != asm.I8 || align != 1 {
		t.Fatalf("armAtomicType(LDREXB) = (%q, %d, %v)", ty, align, err)
	}
	if _, _, err := armAtomicType("BAD"); err == nil {
		t.Fatalf("armAtomicType(BAD) unexpectedly succeeded")
	}
	if got, err := c.atomicExtendToI32("%x", asm.I8); err != nil || got == "" {
		t.Fatalf("atomicExtendToI32(I8) = (%q, %v)", got, err)
	}
	if _, err := c.atomicExtendToI32("%x", asm.I64); err == nil {
		t.Fatalf("atomicExtendToI32(I64) unexpectedly succeeded")
	}
	if got, err := c.atomicTruncFromI32("%x", asm.I8); err != nil || got == "" {
		t.Fatalf("atomicTruncFromI32(I8) = (%q, %v)", got, err)
	}
	if _, err := c.atomicTruncFromI32("%x", asm.I64); err == nil {
		t.Fatalf("atomicTruncFromI32(I64) unexpectedly succeeded")
	}
	if ok, _, err := c.lowerAtomic("LDREX", asm.Instr{Raw: "LDREX R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(LDREX invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerAtomic("STREX", asm.Instr{Raw: "STREX R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(STREX invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerAtomic("STREXD", asm.Instr{Raw: "STREXD R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerAtomic(STREXD invalid) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM", asm.Instr{Raw: "MOVM R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); !ok || err == nil {
		t.Fatalf("lowerMOVM(invalid operands) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM", asm.Instr{Raw: "MOVM (R1), [F0]", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R1"}}, {Kind: asm.OpRegList, RegList: []asm.Reg{"F0"}}}}); !ok || err == nil {
		t.Fatalf("lowerMOVM(non-gpr) = (%v, %v), want error", ok, err)
	}
	if ok, term, err := c.lowerData("MOVD", "", false, asm.Instr{Raw: "MOVD F0, F1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, {Kind: asm.OpReg, Reg: "F1"}}}); !ok || term || err != nil {
		t.Fatalf("lowerData(MOVD freg->freg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerData("MOVD", "", false, asm.Instr{Raw: "MOVD R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); !ok || err == nil {
		t.Fatalf("lowerData(MOVD invalid) = (%v, %v), want error", ok, err)
	}
	for _, ins := range []asm.Instr{
		{Op: "MOVH", Raw: "MOVH R0, 2(R1)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: "R1", Off: 2}}}},
		{Op: "MOVH", Raw: "MOVH R0, half<>(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpSym, Sym: "half<>(SB)"}}},
	} {
		if ok, term, err := c.lowerData("MOVH", "", false, ins); !ok || term || err != nil {
			t.Fatalf("lowerData(%q) = (%v, %v, %v)", ins.Raw, ok, term, err)
		}
	}

	emitBr := func(string) {}
	emitCondBr := func(string, string, string) error { return nil }
	if term, err := c.lowerInstr(0, asm.Instr{Op: "PCDATA", Raw: "PCDATA"}, emitBr, emitCondBr); term || err != nil {
		t.Fatalf("lowerInstr(PCDATA) = (%v, %v)", term, err)
	}
	if term, err := c.lowerInstr(0, asm.Instr{Op: "UNDEF", Raw: "UNDEF"}, emitBr, emitCondBr); !term || err != nil {
		t.Fatalf("lowerInstr(UNDEF) = (%v, %v)", term, err)
	}
	if _, err := c.lowerInstr(0, asm.Instr{Op: "UNKNOWN", Raw: "UNKNOWN"}, emitBr, emitCondBr); err == nil {
		t.Fatalf("lowerInstr(UNKNOWN) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{"store i64", `call void asm sideeffect "udf #0"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMBranchAndSyscallExtraEdges(t *testing.T) {
	c, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.branch2", Ret: asm.Void}, map[string]asm.FuncSig{
		"example.argbad": {Name: "example.argbad", Args: []asm.LLVMType{asm.LLVMType("vec")}, Ret: asm.Void},
	})
	c.blocks = []armBlock{{name: "entry"}}

	emitBr := func(string) {}
	emitCondBr := func(string, string, string) error { return nil }
	if ok, _, err := c.lowerBranch(0, "CALL", "EQ", asm.Instr{Raw: "CALL.EQ R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL cond) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "CALL", "", asm.Instr{Raw: "CALL", Args: nil}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL no args) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "CALL", "", asm.Instr{Raw: "CALL $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(CALL bad target) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "B", "EQ", asm.Instr{Raw: "B.EQ done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(B.EQ no fallthrough) = (%v, %v), want error", ok, err)
	}
	if ok, _, err := c.lowerBranch(0, "BCC", "", asm.Instr{Raw: "BCC done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(BCC no fallthrough) = (%v, %v), want error", ok, err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "argbad(SB)"}); err == nil {
		t.Fatalf("callSym(argbad) unexpectedly succeeded")
	}

	c2, b2 := newARMCtxForTest(t, asm.FuncSig{Name: "example.sys", Ret: asm.I32}, nil)
	delete(c2.regSlot, asm.Reg("R4"))
	delete(c2.regSlot, asm.Reg("R5"))
	if ok, _, err := c2.lowerSyscall("SWI", asm.Instr{Raw: "SWI $0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0}}}); !ok || err != nil {
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
	mk := func(ret asm.LLVMType) *armCtx {
		c, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.branch_exact", Ret: ret}, map[string]asm.FuncSig{
			"example.voidsink": {Name: "example.voidsink", Ret: asm.Void},
			"example.badarg":   {Name: "example.badarg", Args: []asm.LLVMType{asm.LLVMType("vec")}, Ret: asm.Void},
		})
		c.blocks = []armBlock{{name: "entry"}, {name: "fall"}}
		return c
	}
	emitBr := func(string) {}
	errCond := func(string, string, string) error { return errTestSentinel }

	c := mk(asm.Void)
	delete(c.regSlot, asm.Reg("R0"))
	if _, _, err := c.lowerBranch(0, "CALL", "", asm.Instr{Raw: "CALL R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(CALL reg load error) unexpectedly succeeded")
	}

	c = mk(asm.Void)
	delete(c.regSlot, asm.Reg("R1"))
	if _, _, err := c.lowerBranch(0, "CALL", "", asm.Instr{Raw: "CALL (R1)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R1"}}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(CALL mem addr error) unexpectedly succeeded")
	}

	c = mk(asm.Void)
	if _, _, err := c.lowerBranch(0, "B", "", asm.Instr{Raw: "B", Args: nil}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B missing arg) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "EQ", asm.Instr{Raw: "B.EQ R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B.EQ bad target) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "EQ", asm.Instr{Raw: "B.EQ done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, errCond); err == nil {
		t.Fatalf("lowerBranch(B.EQ emit error) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "B", "", asm.Instr{Raw: "B $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(B bad target) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "BEQ", "", asm.Instr{Raw: "BEQ", Args: nil}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(BEQ missing arg) unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, "BEQ", "", asm.Instr{Raw: "BEQ R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}, emitBr, func(string, string, string) error { return nil }); err == nil {
		t.Fatalf("lowerBranch(BEQ bad target) unexpectedly succeeded")
	}

	var got string
	condCapture := func(cond, _, _ string) error { got = cond; return errTestSentinel }
	if _, _, err := c.lowerBranch(0, "BCS", "", asm.Instr{Raw: "BCS done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, condCapture); err == nil || got != "HS" {
		t.Fatalf("lowerBranch(BCS) = (%q, %v)", got, err)
	}
	got = ""
	if _, _, err := c.lowerBranch(0, "BCC", "", asm.Instr{Raw: "BCC done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, condCapture); err == nil || got != "LO" {
		t.Fatalf("lowerBranch(BCC) = (%q, %v)", got, err)
	}

	c = mk(asm.I32)
	if err := c.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "voidsink(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(void sink) error = %v", err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "missing(SB)"}); err != nil {
		t.Fatalf("callSym(missing sig) error = %v", err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "badarg(SB)"}); err == nil {
		t.Fatalf("callSym(bad arg type) unexpectedly succeeded")
	}
}

func TestARMArithErrorCoverage(t *testing.T) {
	c, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.arith_err", Ret: asm.Void}, nil)
	if err := c.lowerARMALU("ADD", "", false, asm.Instr{Raw: "ADD R0, $1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMALU(dst not reg 2-arg) unexpectedly succeeded")
	}
	if err := c.lowerARMALU("ADD", "", false, asm.Instr{Raw: "ADD R0, R1, $2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpImm, Imm: 2}}}); err == nil {
		t.Fatalf("lowerARMALU(dst not reg 3-arg) unexpectedly succeeded")
	}
	if err := c.lowerARMALU("ADD", "", false, asm.Instr{Raw: "ADD bad+8(FP), R0", Args: []asm.Operand{{Kind: asm.OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(src eval err) unexpectedly succeeded")
	}
	delete(c.regSlot, asm.Reg("R0"))
	if err := c.lowerARMALU("ADD", "", false, asm.Instr{Raw: "ADD $1, R0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(loadReg err) unexpectedly succeeded")
	}

	c, _ = newARMCtxForTest(t, asm.FuncSig{Name: "example.arith_err2", Ret: asm.Void}, nil)
	if err := c.lowerARMALU("RSB", "", true, asm.Instr{Raw: "RSB.S $1, R0, R1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMALU(RSB.S) error = %v", err)
	}
	if err := c.lowerARMALU("ORR", "", true, asm.Instr{Raw: "ORR.S R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err != nil {
		t.Fatalf("lowerARMALU(ORR.S) error = %v", err)
	}
	if err := c.lowerARMCompare("CMP", "", asm.Instr{Raw: "CMP bad+8(FP), R0", Args: []asm.Operand{{Kind: asm.OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMCompare(src err) unexpectedly succeeded")
	}
	if err := c.lowerARMCompare("CMP", "", asm.Instr{Raw: "CMP R0, bad+8(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpFPAddr, FPName: "bad", FPOffset: 8}}}); err == nil {
		t.Fatalf("lowerARMCompare(lhs err) unexpectedly succeeded")
	}
	cCondCmp, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.cond_cmp_noflags", Ret: asm.Void}, nil)
	for _, op := range []string{"CMP", "CMN", "TST", "TEQ"} {
		if err := cCondCmp.lowerARMCompare(op, "EQ", asm.Instr{Raw: op + ".EQ R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err == nil {
			t.Fatalf("lowerARMCompare(%s.EQ without prior flags) unexpectedly succeeded", op)
		}
	}
	if err := cCondCmp.setFlagsNZCV("VS", "false", "false", "true", "false"); err == nil {
		t.Fatalf("setFlagsNZCV(VS without prior flags) unexpectedly succeeded")
	}
	if err := cCondCmp.setFlagsNZCV("", "false", "true", "true", "false"); err != nil {
		t.Fatalf("setFlagsNZCV(unconditional) error = %v", err)
	}
	if err := cCondCmp.setFlagsNZCV("EQ", "true", "false", "false", "true"); err != nil {
		t.Fatalf("setFlagsNZCV(EQ) error = %v", err)
	}
	if err := c.lowerARMMVN("", false, asm.Instr{Raw: "MVN", Args: nil}); err == nil {
		t.Fatalf("lowerARMMVN(len err) unexpectedly succeeded")
	}
	c3, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.arith_err3", Ret: asm.Void}, nil)
	if err := c3.lowerARMMVN("EQ", false, asm.Instr{Raw: "MVN.EQ R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err == nil {
		t.Fatalf("lowerARMMVN(select err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, asm.Instr{Raw: "ADC", Args: nil}); err == nil {
		t.Fatalf("lowerARMADCSBC(len err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, asm.Instr{Raw: "ADC bad+8(FP), R0", Args: []asm.Operand{{Kind: asm.OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(src err) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, asm.Instr{Raw: "ADC R0, bad+8(FP), R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpFPAddr, FPName: "bad", FPOffset: 8}, {Kind: asm.OpReg, Reg: "R1"}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(lhs err) unexpectedly succeeded")
	}

	c4, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.pair_err", Ret: asm.Void}, nil)
	delete(c4.regSlot, asm.Reg("R1"))
	if err := c4.selectRegPairWrite("R1", "R2", "", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(store hi err) unexpectedly succeeded")
	}
	c5, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.pair_err2", Ret: asm.Void}, nil)
	if err := c5.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(cond err) unexpectedly succeeded")
	}
	c6, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.pair_err3", Ret: asm.Void}, nil)
	c6.flagsWritten = true
	delete(c6.regSlot, asm.Reg("R1"))
	if err := c6.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(load hi err) unexpectedly succeeded")
	}
	c7, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.pair_err4", Ret: asm.Void}, nil)
	c7.flagsWritten = true
	delete(c7.regSlot, asm.Reg("R2"))
	if err := c7.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err == nil {
		t.Fatalf("selectRegPairWrite(load lo err) unexpectedly succeeded")
	}
}

func TestARMEvalCoverage(t *testing.T) {
	c, b := newARMCtxForTest(t, asm.FuncSig{
		Name: "example.eval",
		Args: []asm.LLVMType{asm.Ptr, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64, "{ ptr, i64 }"},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: asm.I1, Index: 1, Field: -1},
				{Offset: 8, Type: asm.I8, Index: 2, Field: -1},
				{Offset: 12, Type: asm.I16, Index: 3, Field: -1},
				{Offset: 16, Type: asm.I32, Index: 4, Field: -1},
				{Offset: 20, Type: asm.I64, Index: 5, Field: -1},
				{Offset: 24, Type: asm.I64, Index: 6, Field: 1},
			},
			Results: []asm.FrameSlot{{Offset: 32, Type: asm.I32, Index: 0}},
		},
	}, nil)

	if got, base, inc, err := c.addrI32(asm.MemRef{Base: "R1", Index: "R2", Scale: 4, Off: 8}, true); err != nil || got == "" || base != "R1" || inc != 8 {
		t.Fatalf("addrI32() = (%q, %q, %d, %v)", got, base, inc, err)
	}
	if err := c.updatePostInc("R1", 8); err != nil {
		t.Fatalf("updatePostInc() error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R3"}, 64, false, false); err != nil {
		t.Fatalf("loadMem(64) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R4", Off: 1}, 8, false, true); err != nil {
		t.Fatalf("loadMem(8 signed) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R5"}, 32, false, "7"); err != nil {
		t.Fatalf("storeMem(32) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R6"}, 8, false, "9"); err != nil {
		t.Fatalf("storeMem(8) error = %v", err)
	}

	ops := []asm.Operand{
		{Kind: asm.OpImm, Imm: 7},
		{Kind: asm.OpReg, Reg: "R0"},
		{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftLeft, ShiftAmount: 2},
		{Kind: asm.OpFP, FPName: "p", FPOffset: 0},
		{Kind: asm.OpFP, FPName: "b", FPOffset: 4},
		{Kind: asm.OpFP, FPName: "c", FPOffset: 8},
		{Kind: asm.OpFP, FPName: "d", FPOffset: 12},
		{Kind: asm.OpFP, FPName: "e", FPOffset: 16},
		{Kind: asm.OpFP, FPName: "f", FPOffset: 20},
		{Kind: asm.OpFP, FPName: "agg", FPOffset: 24},
		{Kind: asm.OpFPAddr, FPName: "ret", FPOffset: 32},
		{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R7", Off: 4}},
		{Kind: asm.OpSym, Sym: "$runtime·main+4(SB)"},
		{Kind: asm.OpIdent, Ident: "CS"},
	}
	if got, err := c.evalFPAddr32(asm.Operand{Kind: asm.OpFPAddr, FPName: "argframe", FPOffset: 99}); err != nil || got != "0" {
		t.Fatalf("evalFPAddr32(dynamic) = (%q, %v), want (0, nil)", got, err)
	}
	if got, err := c.evalFPValue32(asm.Operand{Kind: asm.OpFP, FPName: "f_hi", FPOffset: 24}); err != nil || got == "" {
		t.Fatalf("evalFPValue32(split i64 high) = (%q, %v)", got, err)
	}
	for _, op := range ops {
		if got, err := c.eval32(op, op.Kind == asm.OpMem); err != nil || got == "" {
			t.Fatalf("eval32(%s) = (%q, %v)", op.String(), got, err)
		}
	}
	if _, err := c.eval32(asm.Operand{Kind: asm.OpImm, ImmRaw: "$(bad)"}, false); err == nil {
		t.Fatalf("eval32(unresolved imm) unexpectedly succeeded")
	}
	if _, err := c.evalShift(asm.Operand{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftRotate, ShiftReg: "R1"}); err != nil {
		t.Fatalf("evalShift(register rotate) error = %v", err)
	}

	out := b.String()
	for _, want := range []string{
		"mul i32",
		"sext i8",
		"store i32 7, ptr",
		"trunc i32 9 to i8",
		"extractvalue { ptr, i64 } %arg6, 1",
		`getelementptr i8, ptr @"runtime.main", i32 4`,
		"ptrtoint ptr",
		"call i32 @llvm.fshr.i32",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMFPAndRetCoverage(t *testing.T) {
	t.Run("StoreAndLoadFPResults", func(t *testing.T) {
		c, b := newARMCtxForTest(t, asm.FuncSig{
			Name: "example.fp",
			Ret:  asm.I64,
			Frame: asm.FrameLayout{
				Results: []asm.FrameSlot{
					{Offset: 8, Type: asm.I32, Index: 0},
					{Offset: 16, Type: asm.I1, Index: 1},
					{Offset: 24, Type: asm.Ptr, Index: 2},
					{Offset: 32, Type: asm.I64, Index: 3},
				},
			},
		}, nil)

		if _, ok := c.fpResultSlotByOffset(8); !ok {
			t.Fatalf("fpResultSlotByOffset(8) not found")
		}
		if _, ok := c.fpResultSlotByOffset(99); ok {
			t.Fatalf("fpResultSlotByOffset(99) unexpectedly found")
		}
		if err := c.storeFPResult32(8, "11"); err != nil {
			t.Fatalf("storeFPResult32(i32) error = %v", err)
		}
		if err := c.storeFPResult32(16, "1"); err != nil {
			t.Fatalf("storeFPResult32(i1) error = %v", err)
		}
		if err := c.storeFPResult32(24, "12"); err != nil {
			t.Fatalf("storeFPResult32(ptr) error = %v", err)
		}
		if err := c.storeFPResult32(32, "13"); err != nil {
			t.Fatalf("storeFPResult32(i64) error = %v", err)
		}
		if _, err := c.loadFPResult(asm.FrameSlot{Index: 3, Type: asm.I64}); err != nil {
			t.Fatalf("loadFPResult() error = %v", err)
		}
		if _, err := c.loadFPResult(asm.FrameSlot{Index: 99, Type: asm.I64}); err == nil {
			t.Fatalf("loadFPResult(missing) unexpectedly succeeded")
		}
		if _, err := c.loadRetSlotFallback(asm.FrameSlot{Type: asm.I16}); err != nil {
			t.Fatalf("loadRetSlotFallback(i16) error = %v", err)
		}

		out := b.String()
		for _, want := range []string{
			"store i32 11, ptr %fp_ret_0",
			"trunc i32 1 to i1",
			"inttoptr i32 12 to ptr",
			"zext i32 13 to i64",
			"load i64, ptr %fp_ret_3",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("LowerRETVariants", func(t *testing.T) {
		for _, tc := range []struct {
			ret  asm.LLVMType
			want string
		}{
			{ret: asm.Void, want: "ret void"},
			{ret: asm.I1, want: "ret i1"},
			{ret: asm.I8, want: "ret i8"},
			{ret: asm.I16, want: "ret i16"},
			{ret: asm.I32, want: "ret i32"},
			{ret: asm.Ptr, want: "ret ptr"},
		} {
			c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.ret", Ret: tc.ret}, nil)
			if err := c.lowerRET(); err != nil {
				t.Fatalf("lowerRET(%s) error = %v", tc.ret, err)
			}
			if !strings.Contains(b.String(), tc.want) {
				t.Fatalf("lowerRET(%s) missing %q in:\n%s", tc.ret, tc.want, b.String())
			}
		}

		c1, b1 := newARMCtxForTest(t, asm.FuncSig{
			Name: "example.ret1",
			Ret:  asm.I32,
			Frame: asm.FrameLayout{
				Results: []asm.FrameSlot{{Offset: 8, Type: asm.I32, Index: 0}},
			},
		}, nil)
		if err := c1.storeFPResult32(8, "99"); err != nil {
			t.Fatalf("storeFPResult32() error = %v", err)
		}
		if err := c1.lowerRET(); err != nil {
			t.Fatalf("lowerRET(single written) error = %v", err)
		}
		if !strings.Contains(b1.String(), "ret i32 %t") {
			t.Fatalf("lowerRET(single written) missing loaded return in:\n%s", b1.String())
		}

		c2, b2 := newARMCtxForTest(t, asm.FuncSig{
			Name: "example.rettuple",
			Ret:  "{ i32, ptr }",
			Frame: asm.FrameLayout{
				Results: []asm.FrameSlot{
					{Offset: 8, Type: asm.I32, Index: 0},
					{Offset: 16, Type: asm.Ptr, Index: 1},
				},
			},
		}, nil)
		if err := c2.storeFPResult32(8, "5"); err != nil {
			t.Fatalf("storeFPResult32(tuple) error = %v", err)
		}
		c2.markFPResultAddrTaken(16)
		if err := c2.lowerRET(); err != nil {
			t.Fatalf("lowerRET(tuple) error = %v", err)
		}
		for _, want := range []string{"insertvalue { i32, ptr }", "ret { i32, ptr }"} {
			if !strings.Contains(b2.String(), want) {
				t.Fatalf("lowerRET(tuple) missing %q in:\n%s", want, b2.String())
			}
		}

		c3, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.bad", Ret: asm.LLVMType("token")}, nil)
		if err := c3.lowerRET(); err == nil {
			t.Fatalf("lowerRET(unsupported) unexpectedly succeeded")
		}

		c4, b4 := newARMCtxForTest(t, asm.FuncSig{
			Name: "example.ret64split",
			Ret:  asm.I64,
			Frame: asm.FrameLayout{Results: []asm.FrameSlot{
				{Offset: 0, Type: asm.I32, Index: 0},
				{Offset: 4, Type: asm.I32, Index: 1},
			}},
		}, nil)
		if err := c4.storeFPResult32(0, "1"); err != nil {
			t.Fatal(err)
		}
		if err := c4.storeFPResult32(4, "2"); err != nil {
			t.Fatal(err)
		}
		if err := c4.lowerRET(); err != nil {
			t.Fatalf("lowerRET(split i64) error = %v", err)
		}
		for _, want := range []string{"zext i32", "shl i64", "or i64", "ret i64"} {
			if !strings.Contains(b4.String(), want) {
				t.Fatalf("lowerRET(split i64) missing %q in:\n%s", want, b4.String())
			}
		}

		c5, b5 := newARMCtxForTest(t, asm.FuncSig{
			Name:  "example.ret64writes",
			Ret:   asm.I64,
			Frame: asm.FrameLayout{Results: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0}}},
		}, nil)
		if err := c5.storeFPResult32(0, "1"); err != nil {
			t.Fatal(err)
		}
		if err := c5.storeFPResult32(4, "2"); err != nil {
			t.Fatal(err)
		}
		if err := c5.lowerRET(); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"and i64", "shl i64", "or i64", "ret i64"} {
			if !strings.Contains(b5.String(), want) {
				t.Fatalf("split i64 writes missing %q in:\n%s", want, b5.String())
			}
		}
	})
}

func TestARMArithCoverageDeep(t *testing.T) {
	c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.arith", Ret: asm.Void}, nil)

	if err := c.lowerARMCompare("CMP", "", asm.Instr{Raw: "CMP R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMCompare(CMP) error = %v", err)
	}
	for _, ins := range []struct {
		op       string
		cond     string
		setFlags bool
		ins      asm.Instr
	}{
		{op: "ADD", setFlags: true, ins: asm.Instr{Raw: "ADD $1, R0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: "R0"}}}},
		{op: "SUB", ins: asm.Instr{Raw: "SUB R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}},
		{op: "AND", cond: "EQ", setFlags: true, ins: asm.Instr{Raw: "AND.EQ.S R0, R2, R3", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R2"}, {Kind: asm.OpReg, Reg: "R3"}}}},
		{op: "ORR", ins: asm.Instr{Raw: "ORR R1, R3, R4", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R3"}, {Kind: asm.OpReg, Reg: "R4"}}}},
		{op: "EOR", ins: asm.Instr{Raw: "EOR R2, R4, R5", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R2"}, {Kind: asm.OpReg, Reg: "R4"}, {Kind: asm.OpReg, Reg: "R5"}}}},
		{op: "RSB", ins: asm.Instr{Raw: "RSB $10, R5, R6", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 10}, {Kind: asm.OpReg, Reg: "R5"}, {Kind: asm.OpReg, Reg: "R6"}}}},
		{op: "BIC", setFlags: true, ins: asm.Instr{Raw: "BIC.S $1, R6, R7", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: "R6"}, {Kind: asm.OpReg, Reg: "R7"}}}},
	} {
		if err := c.lowerARMALU(ins.op, ins.cond, ins.setFlags, ins.ins); err != nil {
			t.Fatalf("lowerARMALU(%s) error = %v", ins.op, err)
		}
	}
	for _, op := range []string{"CMN", "TST", "TEQ"} {
		if err := c.lowerARMCompare(op, "", asm.Instr{Raw: op + " R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err != nil {
			t.Fatalf("lowerARMCompare(%s) error = %v", op, err)
		}
		if err := c.lowerARMCompare(op, "EQ", asm.Instr{Raw: op + ".EQ R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err != nil {
			t.Fatalf("lowerARMCompare(%s.EQ) error = %v", op, err)
		}
	}
	if err := c.lowerARMMVN("EQ", true, asm.Instr{Raw: "MVN.EQ.S R0, R8", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R8"}}}); err != nil {
		t.Fatalf("lowerARMMVN() error = %v", err)
	}
	if err := c.lowerARMADCSBC("ADC", "EQ", true, asm.Instr{Raw: "ADC.EQ.S R1, R8, R9", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R8"}, {Kind: asm.OpReg, Reg: "R9"}}}); err != nil {
		t.Fatalf("lowerARMADCSBC(ADC) error = %v", err)
	}
	if err := c.lowerARMADCSBC("SBC", "", true, asm.Instr{Raw: "SBC.S R1, R9, R10", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R9"}, {Kind: asm.OpReg, Reg: "R10"}}}); err != nil {
		t.Fatalf("lowerARMADCSBC(SBC) error = %v", err)
	}
	if err := c.lowerARMMUL("", asm.Instr{Raw: "MUL R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMMUL(2-arg) error = %v", err)
	}
	if err := c.lowerARMMUL("EQ", asm.Instr{Raw: "MUL.EQ R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err != nil {
		t.Fatalf("lowerARMMUL(3-arg) error = %v", err)
	}
	if err := c.lowerARMMULLU("EQ", asm.Instr{Raw: "MULLU.EQ R0, R1, (R3, R4)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpRegList, RegList: []asm.Reg{"R3", "R4"}}}}); err != nil {
		t.Fatalf("lowerARMMULLU() error = %v", err)
	}
	if err := c.lowerARMMULA("", asm.Instr{Raw: "MULA R0, R1, R2, R5", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}, {Kind: asm.OpReg, Reg: "R5"}}}); err != nil {
		t.Fatalf("lowerARMMULA() error = %v", err)
	}
	if err := c.lowerARMMULAL("EQ", asm.Instr{Raw: "MULAL.EQ R0, R1, (R6, R7)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpRegList, RegList: []asm.Reg{"R6", "R7"}}}}); err != nil {
		t.Fatalf("lowerARMMULAL() error = %v", err)
	}
	if err := c.lowerARMMULAWT("", asm.Instr{Raw: "MULAWT R0, R1, R2, R8", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}, {Kind: asm.OpReg, Reg: "R8"}}}); err != nil {
		t.Fatalf("lowerARMMULAWT() error = %v", err)
	}
	if err := c.lowerARMDIVUHW("EQ", asm.Instr{Raw: "DIVUHW.EQ R1, R2, R9", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}, {Kind: asm.OpReg, Reg: "R9"}}}); err != nil {
		t.Fatalf("lowerARMDIVUHW() error = %v", err)
	}
	if err := c.lowerARMCLZ("", asm.Instr{Raw: "CLZ R9, R10", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R9"}, {Kind: asm.OpReg, Reg: "R10"}}}); err != nil {
		t.Fatalf("lowerARMCLZ() error = %v", err)
	}
	if err := c.lowerARMMRC(asm.Instr{Raw: "MRC $15, $0, R11, $1, $0, $0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 15}, {Kind: asm.OpImm, Imm: 0}, {Kind: asm.OpReg, Reg: "R11"}, {Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpImm, Imm: 0}, {Kind: asm.OpImm, Imm: 0}}}); err != nil {
		t.Fatalf("lowerARMMRC() error = %v", err)
	}
	if ok, _, err := c.lowerArith("MULU", "", false, asm.Instr{Raw: "MULU R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); !ok || err != nil {
		t.Fatalf("lowerArith(MULU) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerArith("UNKNOWN", "", false, asm.Instr{}); ok || err != nil {
		t.Fatalf("lowerArith(UNKNOWN) = (%v, %v), want (false, nil)", ok, err)
	}
	if err := c.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err != nil {
		t.Fatalf("selectRegPairWrite(EQ) error = %v", err)
	}
	if err := c.lowerARMALU("ADD", "", false, asm.Instr{Raw: "ADD R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMCompare("CMP", "", asm.Instr{Raw: "CMP R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMCompare(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMVN("", false, asm.Instr{Raw: "MVN R0, $1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMMVN(invalid dst) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, asm.Instr{Raw: "ADC R0, $1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(invalid dst) unexpectedly succeeded")
	}
	if err := c.lowerARMMULLU("", asm.Instr{Raw: "MULLU R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULLU(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULA("", asm.Instr{Raw: "MULA R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULA(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULAL("", asm.Instr{Raw: "MULAL R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULAL(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULAWT("", asm.Instr{Raw: "MULAWT R0, R1, R2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}, {Kind: asm.OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULAWT(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMDIVUHW("", asm.Instr{Raw: "DIVUHW R0, R1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpReg, Reg: "R1"}}}); err == nil {
		t.Fatalf("lowerARMDIVUHW(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMCLZ("", asm.Instr{Raw: "CLZ R0, $1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}, {Kind: asm.OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMCLZ(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMRC(asm.Instr{Raw: "MRC $15, R0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 15}, {Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMMRC(invalid) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"add i32",
		"sub i32",
		"and i32",
		"or i32",
		"xor i32",
		"mul i64",
		"udiv i32",
		"call i32 @llvm.ctlz.i32",
		`asm sideeffect "mrc p15, 0, $0, 1, 0, 0"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMBranchMovmAndSyscallCoverage(t *testing.T) {
	sigs := map[string]asm.FuncSig{
		"example.helper": {Name: "example.helper", Ret: asm.Void},
		"example.tail":   {Name: "example.tail", Ret: asm.Void},
	}
	c, b := newARMCtxForTest(t, asm.FuncSig{Name: "example.branch", Ret: asm.Void}, sigs)
	c.flagsWritten = true
	c.blocks = []armBlock{{name: "entry"}, {name: "fall"}}

	var gotBr string
	var gotCond [3]string
	emitBr := func(target string) { gotBr = target }
	emitCondBr := func(cond, target, fall string) error {
		gotCond = [3]string{cond, target, fall}
		return nil
	}
	if ok, term, err := c.lowerBranch(0, "JMP", "", asm.Instr{Raw: "JMP loop", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "loop"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP) = (%v, %v, %v)", ok, term, err)
	}
	if gotBr != "loop" {
		t.Fatalf("emitBr target = %q, want loop", gotBr)
	}
	if ok, term, err := c.lowerBranch(0, "B", "EQ", asm.Instr{Raw: "B.EQ done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(B.EQ) = (%v, %v, %v)", ok, term, err)
	}
	if gotCond != [3]string{"EQ", "done", "fall"} {
		t.Fatalf("emitCondBr args = %#v", gotCond)
	}
	if ok, term, err := c.lowerBranch(0, "B", "", asm.Instr{Raw: "B tail(SB)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "tail(SB)"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(B sym) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "BEQ", "", asm.Instr{Raw: "BEQ done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(BEQ) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "BHI", "", asm.Instr{Raw: "BHI done", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(BHI) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "CALL", "", asm.Instr{Raw: "CALL helper(SB)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "helper(SB)"}}}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL sym) = (%v, %v, %v)", ok, term, err)
	}

	if ok, _, err := c.lowerMOVM("MOVM.IB", asm.Instr{Raw: "MOVM.IB (R13), [R0,R1]", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R13"}}, {Kind: asm.OpRegList, RegList: []asm.Reg{"R0", "R1"}}}}); !ok || err != nil {
		t.Fatalf("lowerMOVM(IB load) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM.DA", asm.Instr{Raw: "MOVM.DA [R2,R3], (R13)", Args: []asm.Operand{{Kind: asm.OpRegList, RegList: []asm.Reg{"R2", "R3"}}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: "R13"}}}}); !ok || err != nil {
		t.Fatalf("lowerMOVM(DA store) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerSyscall("SWI", asm.Instr{Raw: "SWI $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}}); !ok || err != nil {
		t.Fatalf("lowerSyscall(SWI imm) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerSyscall("SWI", asm.Instr{Raw: "SWI R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerSyscall(SWI invalid) = (%v, %v), want error", ok, err)
	}

	c2, _ := newARMCtxForTest(t, asm.FuncSig{Name: "example.callers", Ret: asm.I32}, map[string]asm.FuncSig{
		"example.ret32":   {Name: "example.ret32", Ret: asm.I32},
		"example.retVoid": {Name: "example.retVoid", Ret: asm.Void},
		"example.retBad":  {Name: "example.retBad", Ret: asm.LLVMType("vector")},
		"example.tail64":  {Name: "example.tail64", Ret: asm.I64},
	})
	if err := c2.callSym(asm.Operand{Kind: asm.OpSym, Sym: "ret32(SB)"}); err != nil {
		t.Fatalf("callSym(ret32) error = %v", err)
	}
	if err := c2.callSym(asm.Operand{Kind: asm.OpSym, Sym: "retVoid(SB)"}); err != nil {
		t.Fatalf("callSym(retVoid) error = %v", err)
	}
	if err := c2.callSym(asm.Operand{Kind: asm.OpSym, Sym: "retBad(SB)"}); err == nil {
		t.Fatalf("callSym(retBad) unexpectedly succeeded")
	}
	if err := c2.callSym(asm.Operand{Kind: asm.OpReg, Reg: "R0"}); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := c2.callSym(asm.Operand{Kind: asm.OpSym, Sym: "ret32"}); err == nil {
		t.Fatalf("callSym(no sb) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(asm.Operand{Kind: asm.OpReg, Reg: "R0"}); err == nil {
		t.Fatalf("tailCallAndRet(non-sym) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "ret32"}); err == nil {
		t.Fatalf("tailCallAndRet(no sb) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "missing(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(missing sig) error = %v", err)
	}
	if err := c2.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "tail64(SB)"}); err == nil {
		t.Fatalf("tailCallAndRet(mismatch) unexpectedly succeeded")
	}

	cTailPtr, bTailPtr := newARMCtxForTest(t, asm.FuncSig{Name: "example.tailptr", Ret: asm.Ptr}, map[string]asm.FuncSig{
		"example.tailword": {Name: "example.tailword", Ret: asm.I32},
	})
	if err := cTailPtr.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "tailword(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(i32 -> ptr) error = %v", err)
	}
	if got := bTailPtr.String(); !strings.Contains(got, "inttoptr i32") || !strings.Contains(got, "ret ptr") {
		t.Fatalf("tailCallAndRet(i32 -> ptr) output:\n%s", got)
	}

	cTailWord, bTailWord := newARMCtxForTest(t, asm.FuncSig{Name: "example.tailword", Ret: asm.I32}, map[string]asm.FuncSig{
		"example.tailptr": {Name: "example.tailptr", Ret: asm.Ptr},
	})
	if err := cTailWord.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "tailptr(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(ptr -> i32) error = %v", err)
	}
	if got := bTailWord.String(); !strings.Contains(got, "ptrtoint ptr") || !strings.Contains(got, "ret i32") {
		t.Fatalf("tailCallAndRet(ptr -> i32) output:\n%s", got)
	}

	out := b.String()
	for _, want := range []string{
		`call void @"example.tail"()`,
		"ret void",
		"load i32, ptr",
		"store i32",
		"call i64 @syscall(",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
