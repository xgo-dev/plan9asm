package plan9asm

import (
	"strings"
	"testing"
)

func newARMCtxForTest(t *testing.T, sig FuncSig, sigs map[string]FuncSig) (*armCtx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]FuncSig{}
	}
	var b strings.Builder
	c := newARMCtx(&b, Func{}, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		t.Fatalf("emitEntryAllocasAndArgInit() error = %v", err)
	}
	return c, &b
}

func translateARMForTest(t *testing.T, src string, sigs map[string]FuncSig) string {
	t.Helper()
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym: func(sym string) string {
			sym = goStripABISuffix(sym)
			sym = strings.ReplaceAll(sym, "∕", "/")
			if strings.HasPrefix(sym, "runtime·") {
				return strings.ReplaceAll(sym, "·", ".")
			}
			if strings.HasPrefix(sym, "·") {
				return "example." + strings.TrimPrefix(sym, "·")
			}
			if !strings.Contains(sym, "·") && !strings.Contains(sym, ".") && !strings.Contains(sym, "/") {
				return "example." + sym
			}
			return strings.ReplaceAll(sym, "·", ".")
		},
		Sigs: sigs,
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	return ll
}

func TestTranslateARMExtendedArithmetic(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·ops(SB),NOSPLIT,$0-0
	CMP R0, R0
	MVN.EQ.S R0, R1
	ADC.S R1, R2, R3
	SBC.S R1, R2, R4
	MUL R0, R1, R5
	MULLU.EQ R0, R1, (R6, R7)
	MULA R0, R1, R2, R8
	MULAL.EQ R0, R1, (R9, R10)
	MULAWT R0, R1, R2, R11
	DIVUHW R1, R2, R12
	CLZ R12, R0
	MRC $15, $0, R1, $1, $0, $0
	RET
`, map[string]FuncSig{
		"example.ops": {Name: "example.ops", Ret: Void},
	})
	for _, want := range []string{
		"mul i32",
		"mul i64",
		"select i1",
		"call i32 @llvm.ctlz.i32",
		`asm sideeffect "mrc p15, #0, $0, c1, c0, #0"`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
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
		if !armRegListAllGPR([]Reg{"R0", "R7", "R15"}) {
			t.Fatalf("armRegListAllGPR() rejected general-purpose list")
		}
		if armRegListAllGPR([]Reg{"R0", "F0"}) {
			t.Fatalf("armRegListAllGPR() accepted mixed register list")
		}

		if got, ok := armBranchTarget(Operand{Kind: OpIdent, Ident: "loop"}); !ok || got != "loop" {
			t.Fatalf("armBranchTarget(ident) = (%q, %v)", got, ok)
		}
		if got, ok := armBranchTarget(Operand{Kind: OpSym, Sym: "helper<>(SB)"}); !ok || got != "helper" {
			t.Fatalf("armBranchTarget(sym) = (%q, %v)", got, ok)
		}
		if _, ok := armBranchTarget(Operand{Kind: OpReg, Reg: "R0"}); ok {
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

		if got, ok := parseReg("W3"); !ok || got != "R3" {
			t.Fatalf("parseReg(W3) = (%q, %v)", got, ok)
		}
		if got, ok := parseReg("LR"); !ok || got != "R30" {
			t.Fatalf("parseReg(LR) = (%q, %v)", got, ok)
		}
		if got, ok := parseReg("G"); !ok || got != "R28" {
			t.Fatalf("parseReg(G) = (%q, %v)", got, ok)
		}
		if got := (Operand{Kind: OpImm, ImmRaw: "$(a+b)"}).String(); got != "$(a+b)" {
			t.Fatalf("Operand.String() = %q, want unresolved symbolic immediate", got)
		}

		fn := Func{Instrs: []Instr{{Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}}}}}
		if err := validateResolvedImmediates(ArchAMD64, fn); err != nil {
			t.Fatalf("validateResolvedImmediates(amd64) error = %v", err)
		}
		if err := validateResolvedImmediates(ArchARM, fn); err == nil {
			t.Fatalf("validateResolvedImmediates(arm) unexpectedly succeeded")
		}
	})

	t.Run("CtxRetAndStore", func(t *testing.T) {
		c, b := newARMCtxForTest(t, FuncSig{
			Name: "example.f",
			Ret:  I16,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 8, Type: I16, Index: 0}},
			},
		}, nil)
		c.flagsWritten = true

		if err := c.selectRegWrite("R1", "EQ", "7"); err != nil {
			t.Fatalf("selectRegWrite(EQ) error = %v", err)
		}
		if err := c.selectRegWrite("R2", "AL", "9"); err != nil {
			t.Fatalf("selectRegWrite(AL) error = %v", err)
		}
		if err := c.storeARMValue(Operand{Kind: OpFP, FPOffset: 8}, "42", 32, "", false, "MOVW R0, ret+8(FP)"); err != nil {
			t.Fatalf("storeARMValue(FP) error = %v", err)
		}
		if err := c.storeARMValue(Operand{Kind: OpMem, Mem: MemRef{Base: "R3", Off: 4}}, "55", 8, "", false, "MOVB R0, 4(R3)"); err != nil {
			t.Fatalf("storeARMValue(mem) error = %v", err)
		}
		if err := c.storeARMValue(Operand{Kind: OpSym, Sym: "global<>(SB)"}, "1", 32, "", false, "MOVW R0, global<>(SB)"); err != nil {
			t.Fatalf("storeARMValue(sym) error = %v", err)
		}
		if err := c.storeARMValue(Operand{Kind: OpMem, Mem: MemRef{Base: "R3"}}, "1", 32, "EQ", false, "MOVW.EQ R0, (R3)"); err == nil {
			t.Fatalf("storeARMValue(cond mem) unexpectedly succeeded")
		}
		if err := c.storeARMValue(Operand{Kind: OpIdent, Ident: "bad"}, "1", 32, "", false, "bad"); err == nil {
			t.Fatalf("storeARMValue(invalid) unexpectedly succeeded")
		}
		if got, err := c.ptrFromSB("$runtime·main+8(SB)"); err != nil || got == "" {
			t.Fatalf("ptrFromSB() = (%q, %v)", got, err)
		}
		if got, err := c.loadRetSlotFallback(FrameSlot{Type: Ptr}); err != nil || got == "" {
			t.Fatalf("loadRetSlotFallback(ptr) = (%q, %v)", got, err)
		}
		if got, err := c.loadRetSlotFallback(FrameSlot{Type: I64}); err != nil || got == "" {
			t.Fatalf("loadRetSlotFallback(i64) = (%q, %v)", got, err)
		}
		if _, err := c.loadRetSlotFallback(FrameSlot{Type: LLVMType("v4i32")}); err == nil {
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
		sigs := map[string]FuncSig{
			"example.retBool": {Name: "example.retBool", Ret: I1},
			"example.retPtr":  {Name: "example.retPtr", Ret: Ptr},
			"example.ret64":   {Name: "example.ret64", Ret: I64},
			"example.sink": {
				Name:    "example.sink",
				Args:    []LLVMType{I1, I8, I16, I32, Ptr, I64},
				ArgRegs: []Reg{"R0", "R1", "R2", "R3", "R4", "R5"},
				Ret:     Void,
			},
		}
		c, b := newARMCtxForTest(t, FuncSig{Name: "example.caller", Ret: Void}, sigs)

		if err := c.callSym(Operand{Kind: OpSym, Sym: "retBool(SB)"}); err != nil {
			t.Fatalf("callSym(retBool) error = %v", err)
		}
		if err := c.callSym(Operand{Kind: OpSym, Sym: "retPtr(SB)"}); err != nil {
			t.Fatalf("callSym(retPtr) error = %v", err)
		}
		if err := c.callSym(Operand{Kind: OpSym, Sym: "ret64(SB)"}); err != nil {
			t.Fatalf("callSym(ret64) error = %v", err)
		}
		if err := c.callSym(Operand{Kind: OpSym, Sym: "runtime·entersyscall(SB)"}); err != nil {
			t.Fatalf("callSym(runtime·entersyscall) error = %v", err)
		}
		if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "sink(SB)"}); err != nil {
			t.Fatalf("tailCallAndRet() error = %v", err)
		}

		emitBr := func(string) {}
		emitCondBr := func(string, string, string) error { return nil }
		if ok, term, err := c.lowerBranch(0, "CALL", "", Instr{
			Raw:  "CALL R1",
			Args: []Operand{{Kind: OpReg, Reg: "R1"}},
		}, emitBr, emitCondBr); !ok || term || err != nil {
			t.Fatalf("lowerBranch(CALL reg) = (%v, %v, %v)", ok, term, err)
		}
		if ok, term, err := c.lowerBranch(0, "BL", "", Instr{
			Raw:  "BL (R1)",
			Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R1"}}},
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
			ret  LLVMType
			want string
		}{
			{ret: Void, want: "ret void"},
			{ret: I1, want: "ret i1 false"},
			{ret: Ptr, want: "ret ptr null"},
			{ret: I32, want: "ret i32 0"},
		}
		for _, tc := range tests {
			c, b := newARMCtxForTest(t, FuncSig{Name: "example.retzero", Ret: tc.ret}, nil)
			c.lowerRetZero()
			if !strings.Contains(b.String(), tc.want) {
				t.Fatalf("lowerRetZero(%s) missing %q in:\n%s", tc.ret, tc.want, b.String())
			}
		}

		c, b := newARMCtxForTest(t, FuncSig{Name: "example.cast", Ret: Void}, nil)
		for _, ty := range []LLVMType{Ptr, I1, I8, I16, I32, I64} {
			if got, ok, err := armValueAsI32(c, ty, "%v"); err != nil || !ok || got == "" {
				t.Fatalf("armValueAsI32(%s) = (%q, %v, %v)", ty, got, ok, err)
			}
		}
		if _, ok, err := armValueAsI32(c, LLVMType("v2i32"), "%v"); err != nil || ok {
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

func TestTranslateARMBranchesCallsAndShiftForms(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·caller(SB),NOSPLIT,$0-0
	CMP R0, R0
	BEQ ok
	MOVW $1, R0
ok:
	MOVW R1<<2, R2
	MOVW R2>>1, R3
	MOVW R3->1, R4
	MOVW R4@>8, R5
	MOVW R5<<R6, R7
	CALL ·callee(SB)
	MOVW $runtime·main(SB), R2
	RET

TEXT ·callee(SB),NOSPLIT,$0-0
	RET

TEXT ·tail(SB),NOSPLIT,$0-0
	B ·callee(SB)
`, map[string]FuncSig{
		"example.caller": {Name: "example.caller", Ret: Void},
		"example.callee": {Name: "example.callee", Ret: I16},
		"example.tail":   {Name: "example.tail", Ret: I16},
	})
	for _, want := range []string{
		"br i1",
		"call i16 @example.callee()",
		"ptrtoint ptr @runtime.main to i32",
		"shl i32",
		"lshr i32",
		"ashr i32",
		"call i32 @llvm.fshr.i32",
		"trunc i32",
		"ret i16",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}

func TestTranslateARMTailCallAdaptsIntegerReturnWidths(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·boolTail(SB),NOSPLIT,$0-0
	B ·wide(SB)

TEXT ·wide(SB),NOSPLIT,$0-0
	RET
`, map[string]FuncSig{
		"example.boolTail": {Name: "example.boolTail", Ret: I1},
		"example.wide":     {Name: "example.wide", Ret: I64},
	})
	if !strings.Contains(ll, "trunc i64 %") || !strings.Contains(ll, " to i1") {
		t.Fatalf("ARM integer tailcall did not adapt i64 to i1:\n%s", ll)
	}
}

func TestTranslateARMAdditionalAtomicForms(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·atomics(SB),NOSPLIT,$0-0
	LDREXB (R1), R0
	STREXB R3, (R1), R0
	LDREXD (R1), R2
	STREXD R2, (R1), R0
	RET
`, map[string]FuncSig{
		"example.atomics": {Name: "example.atomics", Ret: Void},
	})
	for _, want := range []string{
		"load atomic i8",
		"load atomic i64",
		"cmpxchg ptr",
		"trunc i64",
		"store i1 false, ptr %exclusive_valid",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
