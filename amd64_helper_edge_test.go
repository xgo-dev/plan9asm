package plan9asm

import (
	"strings"
	"testing"
)

func newAMD64CtxWithFuncForTest(t *testing.T, fn Func, sig FuncSig, sigs map[string]FuncSig) (*amd64Ctx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]FuncSig{}
	}
	var b strings.Builder
	c := newAMD64Ctx(&b, fn, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatalf("emitEntryAllocas() error = %v", err)
	}
	return c, &b
}

func TestAMD64CtxHelperEdges(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y2")}, {Kind: OpReg, Reg: Reg("Y3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z4")}, {Kind: OpReg, Reg: Reg("Z5")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K2")}}},
		},
	}
	sig := FuncSig{
		Name: "example.ctx",
		Args: []LLVMType{Ptr, I1, I8, I16, I32, I64, LLVMType("double"), LLVMType("float")},
		Ret:  LLVMType("{i32, ptr, double, float, i16}"),
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I1, Index: 1, Field: -1},
				{Offset: 16, Type: I8, Index: 2, Field: -1},
				{Offset: 24, Type: I16, Index: 3, Field: -1},
				{Offset: 32, Type: I32, Index: 4, Field: -1},
				{Offset: 40, Type: I64, Index: 5, Field: -1},
				{Offset: 48, Type: LLVMType("double"), Index: 6, Field: -1},
				{Offset: 56, Type: LLVMType("float"), Index: 7, Field: -1},
			},
			Results: []FrameSlot{
				{Offset: 80, Type: I32, Index: 0, Field: -1},
				{Offset: 88, Type: Ptr, Index: 1, Field: -1},
				{Offset: 96, Type: LLVMType("double"), Index: 2, Field: -1},
				{Offset: 104, Type: LLVMType("float"), Index: 3, Field: -1},
				{Offset: 112, Type: I16, Index: 4, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)

	for _, ty := range []LLVMType{Ptr, I1, I8, I16, I32, I64} {
		if got, ok, err := amd64ValueAsI64(c, ty, "%v"); err != nil || !ok || got == "" {
			t.Fatalf("amd64ValueAsI64(%s) = (%q, %v, %v)", ty, got, ok, err)
		}
	}
	if got, ok, err := amd64ValueAsI64(c, LLVMType("v2i64"), "%v"); err != nil || ok || got != "" {
		t.Fatalf("amd64ValueAsI64(unsupported) = (%q, %v, %v)", got, ok, err)
	}

	c.pushI64("7")
	if got := c.popI64(); got == "" {
		t.Fatalf("popI64() returned empty value")
	}

	t.Run("VectorRegs", func(t *testing.T) {
		if got, err := c.loadX("X0"); err != nil || got == "" {
			t.Fatalf("loadX(X0) = (%q, %v)", got, err)
		}
		if err := c.storeX("X1", "<16 x i8> zeroinitializer"); err != nil {
			t.Fatalf("storeX(X1) error = %v", err)
		}
		if _, err := c.loadX("AX"); err == nil {
			t.Fatalf("loadX(AX) unexpectedly succeeded")
		}
		if err := c.storeX("AX", "<16 x i8> zeroinitializer"); err == nil {
			t.Fatalf("storeX(AX) unexpectedly succeeded")
		}

		if got, err := c.loadY("Y2"); err != nil || got == "" {
			t.Fatalf("loadY(Y2) = (%q, %v)", got, err)
		}
		if err := c.storeY("Y3", "<32 x i8> zeroinitializer"); err != nil {
			t.Fatalf("storeY(Y3) error = %v", err)
		}
		if _, err := c.loadY("AX"); err == nil {
			t.Fatalf("loadY(AX) unexpectedly succeeded")
		}
		if err := c.storeY("AX", "<32 x i8> zeroinitializer"); err == nil {
			t.Fatalf("storeY(AX) unexpectedly succeeded")
		}

		if got, err := c.loadZ("Z4"); err != nil || got == "" {
			t.Fatalf("loadZ(Z4) = (%q, %v)", got, err)
		}
		if err := c.storeZ("Z5", "<64 x i8> zeroinitializer"); err != nil {
			t.Fatalf("storeZ(Z5) error = %v", err)
		}
		if _, err := c.loadZ("AX"); err == nil {
			t.Fatalf("loadZ(AX) unexpectedly succeeded")
		}
		if err := c.storeZ("AX", "<64 x i8> zeroinitializer"); err == nil {
			t.Fatalf("storeZ(AX) unexpectedly succeeded")
		}

		if got, err := c.loadK("K1"); err != nil || got == "" {
			t.Fatalf("loadK(K1) = (%q, %v)", got, err)
		}
		if err := c.storeK("K2", "9"); err != nil {
			t.Fatalf("storeK(K2) error = %v", err)
		}
		if _, err := c.loadK("AX"); err == nil {
			t.Fatalf("loadK(AX) unexpectedly succeeded")
		}
		if err := c.storeK("AX", "9"); err == nil {
			t.Fatalf("storeK(AX) unexpectedly succeeded")
		}
	})

	t.Run("FlagsAndFP", func(t *testing.T) {
		c.setZFlagFromI64("1")
		c.setZSFlagsFromI64("2")
		c.setZSFlagsFromI32("3")
		c.setCmpFlags("4", "5")
		if got := c.loadFlag(c.flagsZSlot); got == "" {
			t.Fatalf("loadFlag() returned empty value")
		}

		if slot, ok := c.fpParam(32); !ok || slot.Type != I32 {
			t.Fatalf("fpParam(32) = (%#v, %v)", slot, ok)
		}
		if _, ok := c.fpParam(999); ok {
			t.Fatalf("fpParam(999) unexpectedly succeeded")
		}
		if alloca, ty, ok := c.fpResultAlloca(80); !ok || alloca == "" || ty != I32 {
			t.Fatalf("fpResultAlloca(80) = (%q, %q, %v)", alloca, ty, ok)
		}
		if _, _, ok := c.fpResultAlloca(999); ok {
			t.Fatalf("fpResultAlloca(999) unexpectedly succeeded")
		}
		c.markFPResultAddrTaken(88)
		c.markFPResultWritten(80)

		for _, off := range []int64{0, 8, 16, 24, 32, 40, 48, 56} {
			if got, err := c.evalFPToI64(off); err != nil || got == "" {
				t.Fatalf("evalFPToI64(%d) = (%q, %v)", off, got, err)
			}
		}
		if got, err := c.evalFPToF32(56); err != nil || got == "" {
			t.Fatalf("evalFPToF32(float) = (%q, %v)", got, err)
		}
		if got, err := c.evalFPToF32(32); err != nil || got == "" {
			t.Fatalf("evalFPToF32(i32 bits) = (%q, %v)", got, err)
		}
		if _, err := c.evalFPToF32(999); err == nil {
			t.Fatal("evalFPToF32(missing slot) unexpectedly succeeded")
		}
		c.fpParams[64] = FrameSlot{Offset: 64, Type: LLVMType("v4i32"), Index: 0}
		if _, err := c.evalFPToI64(64); err == nil {
			t.Fatalf("evalFPToI64(unsupported type) unexpectedly succeeded")
		}
		if _, err := c.evalFPToF32(64); err == nil {
			t.Fatal("evalFPToF32(unsupported type) unexpectedly succeeded")
		}
		c.fpParams[72] = FrameSlot{Offset: 72, Type: I64, Index: 99}
		if _, err := c.evalFPToI64(72); err == nil {
			t.Fatalf("evalFPToI64(invalid index) unexpectedly succeeded")
		}
		if _, err := c.evalFPToF32(72); err == nil {
			t.Fatal("evalFPToF32(invalid index) unexpectedly succeeded")
		}

		if err := c.storeFPResult(80, I64, "11"); err != nil {
			t.Fatalf("storeFPResult(i64->i32) error = %v", err)
		}
		if err := c.storeFPResult(88, I64, "12"); err != nil {
			t.Fatalf("storeFPResult(i64->ptr) error = %v", err)
		}
		if err := c.storeFPResult(96, I64, "13"); err != nil {
			t.Fatalf("storeFPResult(i64->double) error = %v", err)
		}
		if err := c.storeFPResult(104, LLVMType("float"), "%f"); err != nil {
			t.Fatalf("storeFPResult(float->float) error = %v", err)
		}
		if err := c.storeFPResult(112, I8, "15"); err != nil {
			t.Fatalf("storeFPResult(i8->i16) error = %v", err)
		}
		if err := c.storeFPResult(96, LLVMType("double"), "%x"); err != nil {
			t.Fatalf("storeFPResult(double->double) error = %v", err)
		}
		if err := c.storeFPResult(80, Ptr, "%x"); err == nil {
			t.Fatalf("storeFPResult(ptr->i32) unexpectedly succeeded")
		}

		if got, err := c.loadFPResult(FrameSlot{Index: 0, Type: I32}); err != nil || got == "" {
			t.Fatalf("loadFPResult() = (%q, %v)", got, err)
		}
		if _, err := c.loadFPResult(FrameSlot{Index: 99, Type: I32}); err == nil {
			t.Fatalf("loadFPResult(missing) unexpectedly succeeded")
		}
	})

	t.Run("ReturnHelpers", func(t *testing.T) {
		if !isAMD64FloatRetTy(LLVMType("double")) || !isAMD64FloatRetTy(LLVMType("float")) || isAMD64FloatRetTy(I64) {
			t.Fatalf("isAMD64FloatRetTy() mismatch")
		}
		if got, ok := c.retIntRegByOrd(1); !ok || got != BX {
			t.Fatalf("retIntRegByOrd(1) = (%q, %v)", got, ok)
		}
		if _, ok := c.retIntRegByOrd(-1); ok {
			t.Fatalf("retIntRegByOrd(-1) unexpectedly succeeded")
		}
	})

	if err := c.storeReg(AX, "21"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	if err := c.storeReg(BX, "22"); err != nil {
		t.Fatalf("storeReg(BX) error = %v", err)
	}
	if err := c.storeX("X0", "<16 x i8> zeroinitializer"); err != nil {
		t.Fatalf("storeX(X0) error = %v", err)
	}
	for _, tc := range []struct {
		ord int
		ty  LLVMType
	}{
		{0, I64},
		{1, I32},
		{0, I16},
		{0, I8},
		{0, I1},
		{0, Ptr},
		{0, LLVMType("double")},
		{0, LLVMType("float")},
	} {
		if got, err := c.loadRetIntRegTyped(tc.ord, tc.ty); err != nil || got == "" {
			t.Fatalf("loadRetIntRegTyped(%d, %s) = (%q, %v)", tc.ord, tc.ty, got, err)
		}
	}
	if got, err := c.loadRetIntRegTyped(99, I64); err != nil || got != "0" {
		t.Fatalf("loadRetIntRegTyped(oob) = (%q, %v)", got, err)
	}
	if _, err := c.loadRetIntRegTyped(0, LLVMType("v2i64")); err == nil {
		t.Fatalf("loadRetIntRegTyped(unsupported) unexpectedly succeeded")
	}

	if got, err := c.loadRetFloatRegTyped(0, LLVMType("double")); err != nil || got == "" {
		t.Fatalf("loadRetFloatRegTyped(double) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetFloatRegTyped(0, LLVMType("float")); err != nil || got == "" {
		t.Fatalf("loadRetFloatRegTyped(float) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetFloatRegTyped(99, LLVMType("double")); err != nil || got != "0.000000e+00" {
		t.Fatalf("loadRetFloatRegTyped(oob) = (%q, %v)", got, err)
	}
	if _, err := c.loadRetFloatRegTyped(0, I64); err == nil {
		t.Fatalf("loadRetFloatRegTyped(unsupported) unexpectedly succeeded")
	}

	if isFloat, ord := c.retClassOrdinal(FrameSlot{Index: 3, Type: LLVMType("float")}); !isFloat || ord != 1 {
		t.Fatalf("retClassOrdinal(float) = (%v, %d)", isFloat, ord)
	}
	if got, err := c.loadRetSlotFallback(FrameSlot{Index: 0, Type: I32}); err != nil || got == "" {
		t.Fatalf("loadRetSlotFallback(int) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetSlotFallback(FrameSlot{Index: 2, Type: LLVMType("double")}); err != nil || got == "" {
		t.Fatalf("loadRetSlotFallback(float) = (%q, %v)", got, err)
	}

	for _, tc := range []struct {
		in      string
		wantOK  bool
		wantOff int64
	}{
		{in: "foo<>(SB)", wantOK: true},
		{in: "foo+8(SB)", wantOK: true, wantOff: 8},
		{in: "bare_symbol", wantOK: true},
		{in: "4(AX)", wantOK: false},
		{in: "", wantOK: false},
	} {
		_, off, ok := parseSBRef(tc.in)
		if ok != tc.wantOK || off != tc.wantOff {
			t.Fatalf("parseSBRef(%q) = (%d, %v)", tc.in, off, ok)
		}
	}

	out := b.String()
	for _, want := range []string{
		"alloca <16 x i8>",
		"alloca <32 x i8>",
		"alloca <64 x i8>",
		"alloca i64",
		"ptrtoint ptr %arg0 to i64",
		"load double, ptr %fp_arg_48",
		"load float, ptr %fp_arg_56",
		"trunc i64 11 to i32",
		"inttoptr i64 12 to ptr",
		"bitcast i64 13 to double",
		"store float %f",
		"zext i8 15 to i16",
		"extractelement <2 x i64>",
		"extractelement <4 x i32>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64AtomicAndBranchEdges(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DI}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: SI}, {Kind: OpReg, Reg: DX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("R8")}, {Kind: OpReg, Reg: Reg("R9")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
		},
	}
	sigs := map[string]FuncSig{
		"example.helper": {
			Name:    "example.helper",
			Args:    []LLVMType{I64, I1, I8, I16, I32, Ptr},
			ArgRegs: []Reg{DI, SI, DX, CX, Reg("R8"), Reg("R9")},
			Ret:     Ptr,
		},
		"example.cast": {
			Name: "example.cast",
			Args: []LLVMType{I32, I64},
			Ret:  I64,
		},
		"example.voidret": {
			Name: "example.voidret",
			Args: []LLVMType{I64},
			Ret:  Void,
		},
		"example.badarg": {
			Name: "example.badarg",
			Args: []LLVMType{LLVMType("v2i64")},
			Ret:  I64,
		},
		"example.badret": {
			Name: "example.badret",
			Args: []LLVMType{I64},
			Ret:  LLVMType("double"),
		},
		"example.aggregate": {
			Name: "example.aggregate",
			Ret:  LLVMType("{ ptr, i64 }"),
		},
	}
	sig := FuncSig{
		Name: "example.caller",
		Args: []LLVMType{I64, Ptr},
		Ret:  I64,
		Frame: FrameLayout{
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, sigs)
	c.blocks = []amd64Block{{name: "entry"}, {name: "fall"}, {name: "target"}}
	c.blockBase = []int{0, 1, 2}
	c.blockByIdx = map[int]int{0: 0, 1: 1, 2: 2}

	if ok, term, err := c.lowerAtomic("LOCK", Instr{Raw: "LOCK"}); !ok || term || err != nil {
		t.Fatalf("lowerAtomic(LOCK) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerAtomic("CMPXCHGL", Instr{
		Raw: "CMPXCHGL CX, 8(BX)",
		Args: []Operand{
			{Kind: OpReg, Reg: CX},
			{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(CMPXCHGL) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XADDQ", Instr{
		Raw: "XADDQ AX, 16(BX)",
		Args: []Operand{
			{Kind: OpReg, Reg: AX},
			{Kind: OpMem, Mem: MemRef{Base: BX, Off: 16}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XADDQ) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XCHGB", Instr{
		Raw: "XCHGB AX, BX",
		Args: []Operand{
			{Kind: OpReg, Reg: AX},
			{Kind: OpReg, Reg: BX},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XCHGB reg) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XCHGQ", Instr{
		Raw: "XCHGQ AX, global<>(SB)",
		Args: []Operand{
			{Kind: OpReg, Reg: AX},
			{Kind: OpSym, Sym: "global<>(SB)"},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XCHGQ sym) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("ANDB", Instr{
		Raw: "ANDB $1, 4(BX)",
		Args: []Operand{
			{Kind: OpImm, Imm: 1},
			{Kind: OpMem, Mem: MemRef{Base: BX, Off: 4}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(ANDB) = (%v, %v)", ok, err)
	}
	if ok, term, err := c.lowerAtomic("ORQ", Instr{
		Raw: "ORQ AX, BX",
		Args: []Operand{
			{Kind: OpReg, Reg: AX},
			{Kind: OpReg, Reg: BX},
		},
	}); ok || term || err != nil {
		t.Fatalf("lowerAtomic(non-mem ORQ) = (%v, %v, %v)", ok, term, err)
	}
	if _, err := c.amd64AtomicTruncFromI64("%x", LLVMType("v2i64")); err == nil {
		t.Fatalf("amd64AtomicTruncFromI64(unsupported) unexpectedly succeeded")
	}
	if _, err := c.amd64AtomicExtendToI64("%x", LLVMType("v2i64")); err == nil {
		t.Fatalf("amd64AtomicExtendToI64(unsupported) unexpectedly succeeded")
	}

	emitBr := func(target string) {
		b.WriteString("  br label %" + amd64LLVMBlockName(target) + "\n")
	}
	emitCondBr := func(cond string, target string, fall string) error {
		b.WriteString("  br i1 " + cond + ", label %" + amd64LLVMBlockName(target) + ", label %" + amd64LLVMBlockName(fall) + "\n")
		return nil
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", Instr{
		Raw:  "CALL helper(SB)",
		Args: []Operand{{Kind: OpSym, Sym: "helper(SB)"}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL sym) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", Instr{
		Raw:  "CALL AX",
		Args: []Operand{{Kind: OpReg, Reg: AX}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL reg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", Instr{
		Raw:  "CALL 8(BX)",
		Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL mem) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JEQ", Instr{
		Raw:  "JEQ target",
		Args: []Operand{{Kind: OpIdent, Ident: "target"}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JEQ ident) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JMP", Instr{
		Raw:  "JMP 2(PC)",
		Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: PC, Off: 2}}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP pc-rel) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JMP", Instr{
		Raw:  "JMP AX",
		Args: []Operand{{Kind: OpReg, Reg: AX}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP reg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerBranch(0, 0, "JEQ", Instr{
		Raw:  "JEQ AX",
		Args: []Operand{{Kind: OpReg, Reg: AX}},
	}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(JEQ reg) = (%v, %v), want error", ok, err)
	}

	if err := c.callSym(Operand{Kind: OpSym, Sym: "runtime·entersyscall(SB)"}); err != nil {
		t.Fatalf("callSym(entersyscall) error = %v", err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "helper(SB)"}); err != nil {
		t.Fatalf("callSym(helper) error = %v", err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "aggregate(SB)"}); err != nil {
		t.Fatalf("callSym(aggregate) error = %v", err)
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "badarg(SB)"}); err == nil {
		t.Fatalf("callSym(badarg) unexpectedly succeeded")
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "badret(SB)"}); err == nil {
		t.Fatalf("callSym(badret) unexpectedly succeeded")
	}
	if err := c.callSym(Operand{Kind: OpReg, Reg: AX}); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "missing"}); err == nil {
		t.Fatalf("callSym(missing suffix) unexpectedly succeeded")
	}

	if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "cast(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(cast) error = %v", err)
	}
	if err := c.tailCallAndRet(Operand{Kind: OpSym, Sym: "helper(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(helper) error = %v", err)
	}
	cErr, _ := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Name: "example.errcaller", Args: []LLVMType{I64}, Ret: I64}, sigs)
	if err := cErr.tailCallAndRet(Operand{Kind: OpSym, Sym: "voidret(SB)"}); err == nil {
		t.Fatalf("tailCallAndRet(voidret) unexpectedly succeeded")
	}
	if err := c.tailCallAndRet(Operand{Kind: OpReg, Reg: AX}); err == nil {
		t.Fatalf("tailCallAndRet(non-sym) unexpectedly succeeded")
	}

	var b386 strings.Builder
	c386 := newX86Ctx(&b386, Func{}, FuncSig{Name: "example.ptr386", Ret: Ptr}, testResolveSym("example"), map[string]FuncSig{
		"example.word386": {Name: "example.word386", Ret: I32},
	}, "386", "i386-unknown-linux-gnu", false)
	if err := c386.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	if err := c386.tailCallAndRet(Operand{Kind: OpSym, Sym: "word386(SB)"}); err != nil {
		t.Fatalf("386 tailCallAndRet(i32 -> ptr) error = %v", err)
	}
	if got := b386.String(); !strings.Contains(got, "inttoptr i32") || !strings.Contains(got, "ret ptr") {
		t.Fatalf("386 tailCallAndRet(i32 -> ptr) output:\n%s", got)
	}
	if err := c.tailCallIndirectAddrAndRet("123"); err != nil {
		t.Fatalf("tailCallIndirectAddrAndRet() error = %v", err)
	}

	out := b.String()
	for _, want := range []string{
		"cmpxchg ptr",
		"asm sideeffect \"lock; xadd",
		"asm sideeffect \"xchg",
		"atomicrmw and ptr",
		"icmp eq i8",
		"icmp slt i8",
		"call i64",
		"call ptr @\"example.helper\"",
		"extractvalue { ptr, i64 }",
		"call i64 @\"example.cast\"",
		"ret i64",
		"br i1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64ArithmeticCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: DI}, {Kind: OpReg, Reg: SI}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("R8")}, {Kind: OpReg, Reg: Reg("R9")}}},
		},
	}
	sig := FuncSig{
		Name: "example.arith",
		Ret:  Void,
		Frame: FrameLayout{
			Results: []FrameSlot{
				{Offset: 8, Type: I1, Index: 0, Field: -1},
				{Offset: 16, Type: I64, Index: 1, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	mustLower := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerArith(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerArith(%s) = (%v, %v, %v)", op, ok, term, err)
		}
	}
	if ok, term, err := c.lowerScalarShiftRotate("RCRQ", Instr{Raw: "RCRQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}}); !ok || term || err != nil {
		t.Fatalf("lowerScalarShiftRotate(RCRQ) = (%v, %v, %v)", ok, term, err)
	}

	mustLower("PUSHQ", Instr{Raw: "PUSHQ $1", Args: []Operand{{Kind: OpImm, Imm: 1}}})
	mustLower("POPQ", Instr{Raw: "POPQ CX", Args: []Operand{{Kind: OpReg, Reg: CX}}})
	mustLower("PUSHFQ", Instr{Raw: "PUSHFQ"})
	mustLower("POPFQ", Instr{Raw: "POPFQ"})
	mustLower("LFENCE", Instr{Raw: "LFENCE"})
	mustLower("UNDEF", Instr{Raw: "UNDEF"})
	mustLower("RDTSC", Instr{Raw: "RDTSC"})
	mustLower(OpCPUID, Instr{Raw: "CPUID"})
	mustLower(OpXGETBV, Instr{Raw: "XGETBV"})
	mustLower("RDTSCP", Instr{Raw: "RDTSCP"})
	mustLower("MOVSB", Instr{Raw: "MOVSB"})
	mustLower("MOVSQ", Instr{Raw: "MOVSQ"})
	mustLower("STOSQ", Instr{Raw: "STOSQ"})
	mustLower("NEGL", Instr{Raw: "NEGL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("NEGL", Instr{Raw: "NEGL 4(BX)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 4}}}})
	mustLower("ADDQ", Instr{Raw: "ADDQ $2, AX", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: AX}}})
	mustLower("SUBQ", Instr{Raw: "SUBQ CX, 8(BX)", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}})
	mustLower("XORQ", Instr{Raw: "XORQ $3, AX", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: AX}}})
	mustLower("ANDQ", Instr{Raw: "ANDQ $4, AX", Args: []Operand{{Kind: OpImm, Imm: 4}, {Kind: OpReg, Reg: AX}}})
	mustLower("ORQ", Instr{Raw: "ORQ $5, AX", Args: []Operand{{Kind: OpImm, Imm: 5}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADCQ", Instr{Raw: "ADCQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADCB", Instr{Raw: "ADCB $1, AL", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AL}}})
	mustLower("SBBQ", Instr{Raw: "SBBQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADCXQ", Instr{Raw: "ADCXQ CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADOXQ", Instr{Raw: "ADOXQ CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADDL", Instr{Raw: "ADDL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ADDB", Instr{Raw: "ADDB CL, DX", Args: []Operand{{Kind: OpReg, Reg: CL}, {Kind: OpReg, Reg: DX}}})
	mustLower("SUBL", Instr{Raw: "SUBL CX, 12(BX)", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 12}}}})
	mustLower("XORL", Instr{Raw: "XORL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ANDL", Instr{Raw: "ANDL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ORL", Instr{Raw: "ORL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("XORB", Instr{Raw: "XORB $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ANDB", Instr{Raw: "ANDB $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ORB", Instr{Raw: "ORB $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("INCQ", Instr{Raw: "INCQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("DECQ", Instr{Raw: "DECQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("DECQ", Instr{Raw: "DECQ 96(AX)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Off: 96}}}})
	mustLower("INCL", Instr{Raw: "INCL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("DECL", Instr{Raw: "DECL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("DECL", Instr{Raw: "DECL 12(BX)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 12}}}})
	mustLower("LEAQ", Instr{Raw: "LEAQ 8(BX)(CX*2), DI", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Index: CX, Scale: 2, Off: 8}}, {Kind: OpReg, Reg: DI}}})
	mustLower("LEAL", Instr{Raw: "LEAL 4(BX), SI", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 4}}, {Kind: OpReg, Reg: SI}}})
	mustLower("LEAQ", Instr{Raw: "LEAQ ret+16(FP), R8", Args: []Operand{{Kind: OpFP, FPOffset: 16}, {Kind: OpReg, Reg: Reg("R8")}}})
	mustLower("LEAQ", Instr{Raw: "LEAQ $ret+16(FP), R9", Args: []Operand{{Kind: OpFPAddr, FPOffset: 16}, {Kind: OpReg, Reg: Reg("R9")}}})
	mustLower("LEAQ", Instr{Raw: "LEAQ global<>(SB), AX", Args: []Operand{{Kind: OpSym, Sym: "global<>(SB)"}, {Kind: OpReg, Reg: AX}}})
	mustLower("POPCNTL", Instr{Raw: "POPCNTL AX, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}})
	mustLower("POPCNTQ", Instr{Raw: "POPCNTQ AX, CX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}})
	mustLower("TZCNTQ", Instr{Raw: "TZCNTQ BX, DX", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: DX}}})
	mustLower("BSFQ", Instr{Raw: "BSFQ AX, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}})
	mustLower("BSRQ", Instr{Raw: "BSRQ AX, CX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}})
	mustLower("BSWAPQ", Instr{Raw: "BSWAPQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("BSFL", Instr{Raw: "BSFL AX, DX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: DX}}})
	mustLower("BSRL", Instr{Raw: "BSRL AX, DI", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: DI}}})
	mustLower("SETEQ", Instr{Raw: "SETEQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("SETGT", Instr{Raw: "SETGT ret+8(FP)", Args: []Operand{{Kind: OpFP, FPOffset: 8}}})
	mustLower("SETGE", Instr{Raw: "SETGE AH", Args: []Operand{{Kind: OpReg, Reg: AH}}})
	mustLower("SETHI", Instr{Raw: "SETHI BX", Args: []Operand{{Kind: OpReg, Reg: BX}}})
	mustLower("SETCS", Instr{Raw: "SETCS AL", Args: []Operand{{Kind: OpReg, Reg: AL}}})
	mustLower("SETCS", Instr{Raw: "SETCS AH", Args: []Operand{{Kind: OpReg, Reg: AH}}})
	mustLower("CMOVQEQ", Instr{Raw: "CMOVQEQ CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("CMOVQNE", Instr{Raw: "CMOVQNE CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("CMOVQCS", Instr{Raw: "CMOVQCS CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("CMOVQCC", Instr{Raw: "CMOVQCC CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("CMOVQGT", Instr{Raw: "CMOVQGT CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("ANDNL", Instr{Raw: "ANDNL AX, BX, CX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}})
	mustLower("ANDNQ", Instr{Raw: "ANDNQ AX, BX, DX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: DX}}})
	mustLower("BEXTRQ", Instr{Raw: "BEXTRQ CX, AX, DX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: DX}}})
	mustLower("BZHIQ", Instr{Raw: "BZHIQ DI, AX, CX", Args: []Operand{{Kind: OpReg, Reg: DI}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}})
	mustLower("SHRQ", Instr{Raw: "SHRQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("SHLQ", Instr{Raw: "SHLQ CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("SHLXQ", Instr{Raw: "SHLXQ DI, CX, AX", Args: []Operand{{Kind: OpReg, Reg: DI}, {Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("SARQ", Instr{Raw: "SARQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("SARL", Instr{Raw: "SARL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("SHLL", Instr{Raw: "SHLL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("SHLB", Instr{Raw: "SHLB $2, R10", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("R10")}}})
	mustLower("SHRL", Instr{Raw: "SHRL CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("SHRXQ", Instr{Raw: "SHRXQ DI, AX, CX", Args: []Operand{{Kind: OpReg, Reg: DI}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}})
	mustLower("SALQ", Instr{Raw: "SALQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("SALL", Instr{Raw: "SALL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ROLL", Instr{Raw: "ROLL $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("ROLQ", Instr{Raw: "ROLQ CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("RORQ", Instr{Raw: "RORQ $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	mustLower("RORL", Instr{Raw: "RORL CX, AX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: AX}}})
	mustLower("RORXL", Instr{Raw: "RORXL $1, AX, BX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}})
	mustLower("RORXQ", Instr{Raw: "RORXQ $1, AX, CX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: CX}}})
	mustLower("NOTL", Instr{Raw: "NOTL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("NOTQ", Instr{Raw: "NOTQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("NOTQ", Instr{Raw: "NOTQ 20(BX)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 20}}}})
	mustLower("BSWAPL", Instr{Raw: "BSWAPL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})
	mustLower("MULQ", Instr{Raw: "MULQ CX", Args: []Operand{{Kind: OpReg, Reg: CX}}})
	mustLower("MULXQ", Instr{Raw: "MULXQ BX, CX, DI", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DI}}})
	mustLower("MULL", Instr{Raw: "MULL CX", Args: []Operand{{Kind: OpReg, Reg: CX}}})
	mustLower("DIVL", Instr{Raw: "DIVL CX", Args: []Operand{{Kind: OpReg, Reg: CX}}})
	mustLower("IMULQ", Instr{Raw: "IMULQ CX", Args: []Operand{{Kind: OpReg, Reg: CX}}})
	mustLower("IMULQ", Instr{Raw: "IMULQ CX, DX", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DX}}})
	mustLower("IMUL3Q", Instr{Raw: "IMUL3Q $3, CX, DI", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DI}}})
	mustLower("NEGQ", Instr{Raw: "NEGQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}})

	out := b.String()
	for _, want := range []string{
		`asm sideeffect "cpuid"`,
		`asm sideeffect "xgetbv"`,
		"call i32 @llvm.ctpop.i32",
		"call i64 @llvm.ctpop.i64",
		"call i64 @llvm.cttz.i64",
		"call i32 @llvm.ctlz.i32",
		"call i64 @llvm.bswap.i64",
		"call i32 @llvm.bswap.i32",
		"mul i128",
		"udiv i64",
		"urem i64",
		"select i1",
		"ptrtoint ptr @\"example.global\" to i64",
		"store i8",
		"ashr i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64EcosystemScalarValidationCoverage(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.scalar_validation", Ret: Void}, map[string]FuncSig{
		"example.toowide": {
			Name: "example.toowide",
			Args: []LLVMType{"{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }"},
			Ret:  Void,
		},
		"example.explicit": {
			Name:    "example.explicit",
			Args:    []LLVMType{I64, I64},
			ArgRegs: []Reg{AX},
			Ret:     Void,
		},
	})

	for _, tc := range []struct {
		op  Op
		ins Instr
	}{
		{"BSFQ", Instr{Raw: "BSFQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}},
		{"BSWAPQ", Instr{Raw: "BSWAPQ AX, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}}},
		{"BSRQ", Instr{Raw: "BSRQ AX, BX, CX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}}},
		{"POPCNTL", Instr{Raw: "POPCNTL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}},
	} {
		if _, _, err := c.lowerArith(tc.op, tc.ins); err == nil {
			t.Fatalf("%s %q unexpectedly succeeded", tc.op, tc.ins.Raw)
		}
	}
	for _, op := range []Op{"POPCNTL", "POPCNTQ"} {
		for _, ins := range []Instr{
			{Raw: string(op) + " $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}},
			{Raw: string(op) + " bad, AX", Args: []Operand{{Kind: OpIdent, Ident: "bad"}, {Kind: OpReg, Reg: AX}}},
			{Raw: string(op) + " X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}},
			{Raw: string(op) + " AX, X0", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}},
		} {
			if ok, term, err := c.lowerArith(op, ins); !ok || term || err == nil {
				t.Fatalf("lowerArith(%s) invalid form = (%v, %v, %v), want recognized validation error", op, ok, term, err)
			}
		}
	}

	cursor := 0
	if _, err := c.structArgFromSequentialRegs(LLVMType("v2i64"), []Reg{AX}, &cursor); err == nil {
		t.Fatal("non-aggregate scalar argument unexpectedly succeeded")
	}
	cursor = 0
	if _, err := c.structArgFromSequentialRegs(LLVMType("{ i64 }"), nil, &cursor); err == nil {
		t.Fatal("aggregate exceeding the register list unexpectedly succeeded")
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "toowide(SB)"}); err == nil {
		t.Fatal("aggregate exceeding the Go ABI register list unexpectedly succeeded")
	}
	if err := c.callSym(Operand{Kind: OpSym, Sym: "explicit(SB)"}); err == nil {
		t.Fatal("incomplete explicit argument-register list unexpectedly succeeded")
	}
}

func TestAMD64SetCSUsesCarryFlag(t *testing.T) {
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.setcs", Ret: Void}, nil)
	if err := c.storeReg(AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 true, ptr " + c.flagsCFSlot + "\n")

	for _, ins := range []Instr{
		{Raw: "SETCS AL", Args: []Operand{{Kind: OpReg, Reg: AL}}},
		{Raw: "SETCS AH", Args: []Operand{{Kind: OpReg, Reg: AH}}},
	} {
		if ok, term, err := c.lowerArith("SETCS", ins); !ok || term || err != nil {
			t.Fatalf("lowerArith(%s) = (%v, %v, %v)", ins.Raw, ok, term, err)
		}
	}

	out := b.String()
	for _, want := range []string{
		"store i1 true, ptr %flags_cf",
		"load i1, ptr %flags_cf",
		"select i1 %",
		"shl i64",
		"or i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64SetGEUsesSignedFlag(t *testing.T) {
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.setge", Ret: Void}, nil)
	if err := c.storeReg(AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 false, ptr " + c.flagsSltSlot + "\n")

	ins := Instr{Raw: "SETGE AH", Args: []Operand{{Kind: OpReg, Reg: AH}}}
	if ok, term, err := c.lowerArith("SETGE", ins); !ok || term || err != nil {
		t.Fatalf("lowerArith(%s) = (%v, %v, %v)", ins.Raw, ok, term, err)
	}

	out := b.String()
	for _, want := range []string{
		"store i1 false, ptr %flags_slt",
		"load i1, ptr %flags_slt",
		"xor i1 %",
		"shl i64",
		"or i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64ADCBUsesCarryFlag(t *testing.T) {
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.adcb", Ret: Void}, nil)
	if err := c.storeReg(AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 true, ptr " + c.flagsCFSlot + "\n")

	for _, ins := range []Instr{
		{Raw: "ADCB $1, AL", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AL}}},
		{Raw: "ADCB $1, AH", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AH}}},
	} {
		if ok, term, err := c.lowerArith("ADCB", ins); !ok || term || err != nil {
			t.Fatalf("lowerArith(%s) = (%v, %v, %v)", ins.Raw, ok, term, err)
		}
	}

	out := b.String()
	for _, want := range []string{
		"store i1 true, ptr %flags_cf",
		"load i1, ptr %flags_cf",
		"zext i1 %",
		"add i16",
		"zext i8",
		"icmp ugt i16",
		"shl i64",
		"or i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64VectorCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: DI}, {Kind: OpReg, Reg: SI}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("R8")}, {Kind: OpReg, Reg: Reg("R9")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X2")}, {Kind: OpReg, Reg: Reg("X3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y2")}, {Kind: OpReg, Reg: Reg("Y3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z2")}, {Kind: OpReg, Reg: Reg("Z3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K2")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("K3")}, {Kind: OpReg, Reg: Reg("X4")}}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Name: "example.vec", Ret: Void}, nil)
	mustLower := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerVec(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerVec(%s) = (%v, %v, %v)", op, ok, term, err)
		}
	}

	mustLower("MOVL", Instr{Raw: "MOVL $1, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}}})
	mustLower("MOVD", Instr{Raw: "MOVD AX, X1", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("MOVQ", Instr{Raw: "MOVQ BX, X2", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: Reg("X2")}}})
	mustLower("MOVQ", Instr{Raw: "MOVQ X2, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X2")}, {Kind: OpReg, Reg: AX}}})
	mustLower("KXORQ", Instr{Raw: "KXORQ K1, K2, K3", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K2")}, {Kind: OpReg, Reg: Reg("K3")}}})
	mustLower("KMOVB", Instr{Raw: "KMOVB AX, K1", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("K1")}}})
	mustLower("KMOVW", Instr{Raw: "KMOVW K1, 8(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}})
	mustLower("KMOVQ", Instr{Raw: "KMOVQ K1, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: AX}}})
	mustLower("VPERMB", Instr{Raw: "VPERMB Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPERMB", Instr{Raw: "VPERMB Z0, Z1, K1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VGF2P8AFFINEQB", Instr{Raw: "VGF2P8AFFINEQB $1, Z0, Z1, Z2", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, K1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPOPCNTB", Instr{Raw: "VPOPCNTB Z0, Z1", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}})
	mustLower("VPCMPUQ", Instr{Raw: "VPCMPUQ $1, Z0, Z1, K1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("K1")}}})
	mustLower("VPCOMPRESSQ", Instr{Raw: "VPCOMPRESSQ Z0, K1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPXORQ", Instr{Raw: "VPXORQ Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPANDQ", Instr{Raw: "VPANDQ Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPORQ", Instr{Raw: "VPORQ Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPXOR", Instr{Raw: "VPXOR Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPOR", Instr{Raw: "VPOR Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPADDD", Instr{Raw: "VPADDD Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPADDQ", Instr{Raw: "VPADDQ Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPXOR", Instr{Raw: "VPXOR X0, X1, X2", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X2")}}})
	mustLower("VPSHUFB", Instr{Raw: "VPSHUFB Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPSHUFB", Instr{Raw: "VPSHUFB X0, X1, X2", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X2")}}})
	mustLower("VPSHUFD", Instr{Raw: "VPSHUFD $0x1b, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 0x1b}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPSLLD", Instr{Raw: "VPSLLD $2, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPSRLD", Instr{Raw: "VPSRLD $2, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPSRLQ", Instr{Raw: "VPSRLQ $2, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPSLLQ", Instr{Raw: "VPSLLQ $2, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPALIGNR", Instr{Raw: "VPALIGNR $3, Y0, Y1, Y2", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPERM2I128", Instr{Raw: "VPERM2I128 $0x21, Y0, Y1, Y2", Args: []Operand{{Kind: OpImm, Imm: 0x21}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VINSERTI128", Instr{Raw: "VINSERTI128 $1, X0, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VMOVNTDQ", Instr{Raw: "VMOVNTDQ Y0, 32(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 32}}}})
	mustLower("AESENC", Instr{Raw: "AESENC X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("AESENCLAST", Instr{Raw: "AESENCLAST X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("AESDEC", Instr{Raw: "AESDEC X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("AESDECLAST", Instr{Raw: "AESDECLAST X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("AESIMC", Instr{Raw: "AESIMC X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("AESKEYGENASSIST", Instr{Raw: "AESKEYGENASSIST $1, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("VPTEST", Instr{Raw: "VPTEST Y0, Y1", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("PCMPESTRI", Instr{Raw: "PCMPESTRI $0x0c, 48(BX), X0", Args: []Operand{{Kind: OpImm, Imm: 0x0c}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 48}}, {Kind: OpReg, Reg: Reg("X0")}}})
	mustLower("VPAND", Instr{Raw: "VPAND Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPBLENDD", Instr{Raw: "VPBLENDD $0xaa, Y0, Y1, Y2", Args: []Operand{{Kind: OpImm, Imm: 0xaa}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPBROADCASTB", Instr{Raw: "VPBROADCASTB X0, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}})
	mustLower("VPSRLDQ", Instr{Raw: "VPSRLDQ $3, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VPSLLDQ", Instr{Raw: "VPSLLDQ $3, Y0, Y1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("PUNPCKLBW", Instr{Raw: "PUNPCKLBW X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSHUFL", Instr{Raw: "PSHUFL $0x1b, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 0x1b}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSHUFHW", Instr{Raw: "PSHUFHW $0x1b, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 0x1b}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHUFPS", Instr{Raw: "SHUFPS $0x1b, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 0x1b}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PBLENDW", Instr{Raw: "PBLENDW $0xaa, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 0xaa}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA256MSG1", Instr{Raw: "SHA256MSG1 X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA256MSG2", Instr{Raw: "SHA256MSG2 X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA1NEXTE", Instr{Raw: "SHA1NEXTE X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA1MSG1", Instr{Raw: "SHA1MSG1 X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA1MSG2", Instr{Raw: "SHA1MSG2 X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA1RNDS4", Instr{Raw: "SHA1RNDS4 $1, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("SHA256RNDS2", Instr{Raw: "SHA256RNDS2 X0, X1, X2", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X2")}}})
	mustLower("VMOVDQU64", Instr{Raw: "VMOVDQU64 Z0, 64(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 64}}}})
	mustLower("VMOVDQU64", Instr{Raw: "VMOVDQU64 64(BX), Z1", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 64}}, {Kind: OpReg, Reg: Reg("Z1")}}})
	mustLower("VMOVDQU64", Instr{Raw: "VMOVDQU64 Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VMOVDQU", Instr{Raw: "VMOVDQU Y0, 80(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 80}}}})
	mustLower("VMOVDQU", Instr{Raw: "VMOVDQU 80(BX), Y1", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 80}}, {Kind: OpReg, Reg: Reg("Y1")}}})
	mustLower("VMOVDQU", Instr{Raw: "VMOVDQU X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("VPCMPEQB", Instr{Raw: "VPCMPEQB Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	mustLower("VPMOVMSKB", Instr{Raw: "VPMOVMSKB Y0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: AX}}})
	mustLower("MOVOU", Instr{Raw: "MOVOU 96(BX), X0", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 96}}, {Kind: OpReg, Reg: Reg("X0")}}})
	mustLower("MOVOU", Instr{Raw: "MOVOU X0, 112(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 112}}}})
	mustLower("PXOR", Instr{Raw: "PXOR X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PAND", Instr{Raw: "PAND X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	if ok, term, err := c.lowerPackedAndNot("PANDN", Instr{Raw: "PANDN X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}}); !ok || term || err != nil {
		t.Fatalf("lowerPackedAndNot(PANDN) = (%v, %v, %v)", ok, term, err)
	}
	mustLower("PADDL", Instr{Raw: "PADDL X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PADDQ", Instr{Raw: "PADDQ X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSUBL", Instr{Raw: "PSUBL X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSLLL", Instr{Raw: "PSLLL $1, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSRLL", Instr{Raw: "PSRLL $1, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSRAL", Instr{Raw: "PSRAL $1, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PCMPEQL", Instr{Raw: "PCMPEQL X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("VPCLMULQDQ", Instr{Raw: "VPCLMULQDQ $0x11, Z0, Z1, Z2", Args: []Operand{{Kind: OpImm, Imm: 0x11}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VPTERNLOGD", Instr{Raw: "VPTERNLOGD $0x96, Z0, Z1, Z2", Args: []Operand{{Kind: OpImm, Imm: 0x96}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}})
	mustLower("VEXTRACTF32X4", Instr{Raw: "VEXTRACTF32X4 $1, Z0, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("X0")}}})
	mustLower("PCLMULQDQ", Instr{Raw: "PCLMULQDQ $0x11, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 0x11}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PCMPEQB", Instr{Raw: "PCMPEQB X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PMOVMSKB", Instr{Raw: "PMOVMSKB X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}})
	mustLower("PSHUFB", Instr{Raw: "PSHUFB X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PINSRQ", Instr{Raw: "PINSRQ $1, AX, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PINSRD", Instr{Raw: "PINSRD $1, AX, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PINSRW", Instr{Raw: "PINSRW $1, AX, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PINSRB", Instr{Raw: "PINSRB $1, AX, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PEXTRB", Instr{Raw: "PEXTRB $1, X1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: AX}}})
	mustLower("PEXTRB", Instr{Raw: "PEXTRB $1, X1, 128(BX)", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 128}}}})
	mustLower("PALIGNR", Instr{Raw: "PALIGNR $3, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSRLDQ", Instr{Raw: "PSRLDQ $3, X1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSLLDQ", Instr{Raw: "PSLLDQ $3, X1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PSRLQ", Instr{Raw: "PSRLQ $1, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}}})
	mustLower("PEXTRD", Instr{Raw: "PEXTRD $1, X1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: AX}}})
	mustLower("PEXTRD", Instr{Raw: "PEXTRD $1, X1, 136(BX)", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 136}}}})

	if _, err := c.loadXVecOperand(Operand{Kind: OpReg, Reg: AX}); err == nil {
		t.Fatalf("loadXVecOperand(non-x) unexpectedly succeeded")
	}
	if _, err := c.loadYVecOperand(Operand{Kind: OpReg, Reg: AX}); err == nil {
		t.Fatalf("loadYVecOperand(non-y) unexpectedly succeeded")
	}
	if _, err := c.loadZVecOperand(Operand{Kind: OpReg, Reg: AX}); err == nil {
		t.Fatalf("loadZVecOperand(non-z) unexpectedly succeeded")
	}
	if got := llvmShiftRightBytesMask(3); !strings.Contains(got, "i32 3") || !strings.Contains(got, "i32 16") {
		t.Fatalf("llvmShiftRightBytesMask(3) = %q", got)
	}
	if got := llvmShiftLeftBytesMask(3); !strings.Contains(got, "i32 16") {
		t.Fatalf("llvmShiftLeftBytesMask(3) = %q", got)
	}
	if got := llvmAllOnesI8Vec(4); got != "<i8 -1, i8 -1, i8 -1, i8 -1>" {
		t.Fatalf("llvmAllOnesI8Vec(4) = %q", got)
	}
	if !isAMD64ZReg(Reg("Z0")) || isAMD64ZReg(AX) {
		t.Fatalf("isAMD64ZReg() mismatch")
	}
	if got := amd64SelectZByAnyMask(c, "zeroinitializer", "1"); got == "" {
		t.Fatalf("amd64SelectZByAnyMask() returned empty value")
	}
	pred := c.newTmp()
	b.WriteString("  %" + pred + " = icmp eq <8 x i64> zeroinitializer, zeroinitializer\n")
	if got := amd64PackI1x8ToI64(c, "%"+pred); got == "" {
		t.Fatalf("amd64PackI1x8ToI64() returned empty value")
	}
	if got := amd64BytePopcountZ(c, "zeroinitializer"); got == "" {
		t.Fatalf("amd64BytePopcountZ() returned empty value")
	}

	out := b.String()
	for _, want := range []string{
		"@llvm.x86.aesni.aesenc",
		"@llvm.x86.aesni.aesenclast",
		"@llvm.x86.aesni.aesdec",
		"@llvm.x86.aesni.aesdeclast",
		"@llvm.x86.aesni.aesimc",
		"@llvm.x86.aesni.aeskeygenassist",
		"@llvm.x86.ssse3.pshuf.b.128",
		"@llvm.x86.sse2.pmovmskb.128",
		"@llvm.x86.pclmulqdq",
		"shufflevector <64 x i8>",
		"bitcast <64 x i8>",
		"select <16 x i1>",
		"select <32 x i1>",
		"store <64 x i8>",
		"store <32 x i8>",
		"store <16 x i8>",
		"extractelement <16 x i8>",
		"insertelement <2 x i64>",
		"icmp ult <8 x i64>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64TranslateReturnCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: OpTEXT, Raw: "TEXT ·edge(SB),NOSPLIT,$0-0"},
			{Op: "GET_TLS(CX)", Raw: "GET_TLS(CX)"},
			{Op: "NOP", Raw: "NOP"},
		},
	}
	var translated strings.Builder
	if err := translateFuncAMD64(&translated, fn, FuncSig{Name: "example.edge", Ret: I32}, testResolveSym("example"), nil, true); err != nil {
		t.Fatalf("translateFuncAMD64() error = %v", err)
	}
	if !strings.Contains(translated.String(), "ret i32 0") || !strings.Contains(translated.String(), "; s: NOP") {
		t.Fatalf("translateFuncAMD64() output = \n%s", translated.String())
	}

	for _, tc := range []struct {
		name string
		sig  FuncSig
		want string
	}{
		{"void", FuncSig{Name: "example.retvoid", Ret: Void}, "ret void"},
		{"i1", FuncSig{Name: "example.reti1", Ret: I1}, "ret i1"},
		{"i8", FuncSig{Name: "example.reti8", Ret: I8}, "ret i8"},
		{"i16", FuncSig{Name: "example.reti16", Ret: I16}, "ret i16"},
		{"i32", FuncSig{Name: "example.reti32", Ret: I32}, "ret i32"},
		{"i64", FuncSig{Name: "example.reti64", Ret: I64}, "ret i64"},
	} {
		c, b := newAMD64CtxWithFuncForTest(t, Func{}, tc.sig, nil)
		if tc.sig.Ret != Void {
			if err := c.storeReg(AX, "19"); err != nil {
				t.Fatalf("storeReg(AX) error = %v", err)
			}
		}
		if err := c.lowerRET(); err != nil {
			t.Fatalf("lowerRET(%s) error = %v", tc.name, err)
		}
		if !strings.Contains(b.String(), tc.want) {
			t.Fatalf("lowerRET(%s) output = \n%s", tc.name, b.String())
		}
	}

	cAgg, bAgg := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{
		Name: "example.retagg",
		Ret:  LLVMType("{ i64, i32 }"),
		Frame: FrameLayout{
			Results: []FrameSlot{
				{Offset: 8, Type: I64, Index: 0},
				{Offset: 16, Type: I32, Index: 1},
			},
		},
	}, nil)
	if err := cAgg.storeFPResult(8, I64, "21"); err != nil {
		t.Fatalf("storeFPResult(8) error = %v", err)
	}
	if err := cAgg.lowerRET(); err != nil {
		t.Fatalf("lowerRET(aggregate) error = %v", err)
	}
	if !strings.Contains(bAgg.String(), "insertvalue { i64, i32 }") {
		t.Fatalf("lowerRET(aggregate) output = \n%s", bAgg.String())
	}

	cz, bz := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.zero", Ret: I64}, nil)
	cz.lowerRetZero()
	if !strings.Contains(bz.String(), "ret i64 0") {
		t.Fatalf("lowerRetZero() output = \n%s", bz.String())
	}
}

func TestAMD64FPMovCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X2")}, {Kind: OpReg, Reg: Reg("X3")}}},
		},
	}
	sig := FuncSig{
		Name: "example.fpmov",
		Args: []LLVMType{I64, LLVMType("double"), I64, I64},
		Ret:  Void,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: LLVMType("double"), Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			},
			Results: []FrameSlot{
				{Offset: 40, Type: LLVMType("double"), Index: 0, Field: -1},
				{Offset: 48, Type: I64, Index: 1, Field: -1},
				{Offset: 56, Type: I16, Index: 2, Field: -1},
				{Offset: 64, Type: I8, Index: 3, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	check := func(kind string, ins Instr, ok bool, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s %q error = %v", kind, ins.Raw, err)
		}
		if !ok {
			t.Fatalf("%s %q returned ok=false", kind, ins.Raw)
		}
	}
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "11"},
		{BX, "12"},
		{CX, "13"},
		{DX, "14"},
		{SI, "15"},
		{DI, "16"},
		{Reg("R8"), "17"},
		{Reg("R9"), "18"},
		{Reg("R10"), "19"},
		{Reg("R11"), "20"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	for _, xr := range []Reg{"X0", "X1", "X2", "X3"} {
		if err := c.storeX(xr, "<16 x i8> zeroinitializer"); err != nil {
			t.Fatalf("storeX(%s) error = %v", xr, err)
		}
	}

	for _, ins := range []Instr{
		{Op: "MOVAPD", Args: []Operand{{Kind: OpSym, Sym: "example.vec(SB)"}, {Kind: OpReg, Reg: "X0"}}, Raw: "MOVAPD example.vec(SB), X0"},
		{Op: "ANDPD", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Off: 8}}, {Kind: OpReg, Reg: "X0"}}, Raw: "ANDPD 8(AX), X0"},
		{Op: "ANDNPD", Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}, Raw: "ANDNPD X1, X0"},
		{Op: "ORPD", Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}, Raw: "ORPD X1, X0"},
		{Op: "XORPS", Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X0"}}, Raw: "XORPS X1, X0"},
		{Op: "MOVSD", Args: []Operand{{Kind: OpImm, Imm: 7}, {Kind: OpReg, Reg: "X0"}}, Raw: "MOVSD $7, X0"},
		{Op: "MOVSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 16}}}, Raw: "MOVSD X0, 16(BX)"},
		{Op: "MOVSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpSym, Sym: "example.f64(SB)"}}, Raw: "MOVSD X0, example.f64(SB)"},
		{Op: "MOVSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpFP, FPOffset: 40}}, Raw: "MOVSD X0, ret+40(FP)"},
		{Op: "ADDSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}, Raw: "ADDSD X0, X1"},
		{Op: "SUBSD", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: CX, Off: 8}}, {Kind: OpReg, Reg: "X1"}}, Raw: "SUBSD 8(CX), X1"},
		{Op: "MULSD", Args: []Operand{{Kind: OpSym, Sym: "example.f64(SB)"}, {Kind: OpReg, Reg: "X1"}}, Raw: "MULSD example.f64(SB), X1"},
		{Op: "DIVSD", Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: "X1"}}, Raw: "DIVSD arg+8(FP), X1"},
		{Op: "MAXSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}, Raw: "MAXSD X0, X1"},
		{Op: "MINSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}, Raw: "MINSD X0, X1"},
		{Op: "SQRTSD", Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"}}, Raw: "SQRTSD X1, X2"},
		{Op: "COMISD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}, Raw: "COMISD X0, X1"},
		{Op: "CMPSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpImm, Imm: 7}}, Raw: "CMPSD X0, X1, $7"},
		{Op: "CMPSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpSym, Sym: "5"}}, Raw: "CMPSD X0, X1, 5"},
		{Op: "CVTTSD2SQ", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: AX}}, Raw: "CVTTSD2SQ X0, AX"},
		{Op: "CVTSQ2SD", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: "X2"}}, Raw: "CVTSQ2SD AX, X2"},
		{Op: "CVTSD2SL", Args: []Operand{{Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: BX}}, Raw: "CVTSD2SL X1, BX"},
		{Op: "CVTSL2SD", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: "X0"}}, Raw: "CVTSL2SD AX, X0"},
		{Op: "VADDSD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"}}, Raw: "VADDSD X0, X1, X2"},
		{Op: "VFMADD213SD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"}}, Raw: "VFMADD213SD X0, X1, X2"},
		{Op: "VFNMADD231SD", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"}}, Raw: "VFNMADD231SD X0, X1, X2"},
	} {
		ok, _, err := c.lowerFP(ins.Op, ins)
		check("lowerFP", ins, ok, err)
	}

	c.setCmpFlags("1", "2")
	for _, ins := range []Instr{
		{Op: "CMOVQLT", Args: []Operand{{Kind: OpReg, Reg: CX}, {Kind: OpReg, Reg: DX}}, Raw: "CMOVQLT CX, DX"},
		{Op: "MOVLQSX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}, Raw: "MOVLQSX AX, AX"},
		{Op: "MOVLQSX", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}, Raw: "MOVLQSX BX, CX"},
		{Op: "MOVLQSX", Args: []Operand{{Kind: OpFP, FPOffset: 16}, {Kind: OpReg, Reg: DX}}, Raw: "MOVLQSX arg+16(FP), DX"},
		{Op: "MOVLQSX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: SI, Off: 4}}, {Kind: OpReg, Reg: SI}}, Raw: "MOVLQSX 4(SI), SI"},
		{Op: "MOVLQSX", Args: []Operand{{Kind: OpSym, Sym: "example.i32(SB)"}, {Kind: OpReg, Reg: DI}}, Raw: "MOVLQSX example.i32(SB), DI"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpImm, Imm: 31}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ $31, AX"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: BX}}, Raw: "MOVQ 8(BX), BX"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpSym, Sym: "example.i64(SB)"}, {Kind: OpReg, Reg: CX}}, Raw: "MOVQ example.i64(SB), CX"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 48}}, Raw: "MOVQ AX, ret+48(FP)"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: DX, Off: 8}}}, Raw: "MOVQ AX, 8(DX)"},
		{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "example.i64(SB)"}}, Raw: "MOVQ AX, example.i64(SB)"},
		{Op: "MOVL", Args: []Operand{{Kind: OpImm, Imm: 41}, {Kind: OpReg, Reg: DX}}, Raw: "MOVL $41, DX"},
		{Op: "MOVL", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: SI, Off: 8}}, {Kind: OpReg, Reg: Reg("R8")}}, Raw: "MOVL 8(SI), R8"},
		{Op: "MOVL", Args: []Operand{{Kind: OpSym, Sym: "example.i32(SB)"}, {Kind: OpReg, Reg: Reg("R9")}}, Raw: "MOVL example.i32(SB), R9"},
		{Op: "MOVL", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 48}}, Raw: "MOVL AX, ret+48(FP)"},
		{Op: "MOVL", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: DI, Off: 8}}}, Raw: "MOVL AX, 8(DI)"},
		{Op: "MOVL", Args: []Operand{{Kind: OpImm, Imm: 0xf1}, {Kind: OpImm, Imm: 0xf1}}, Raw: "MOVL $0xf1, 0xf1"},
		{Op: "MOVL", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "example.i32(SB)"}}, Raw: "MOVL AX, example.i32(SB)"},
		{Op: "MOVLQZX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Off: 12}}, {Kind: OpReg, Reg: Reg("R10")}}, Raw: "MOVLQZX 12(AX), R10"},
		{Op: "MOVBQZX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Off: 13}}, {Kind: OpReg, Reg: Reg("R11")}}, Raw: "MOVBQZX 13(AX), R11"},
		{Op: "MOVB", Args: []Operand{{Kind: OpImm, Imm: 9}, {Kind: OpReg, Reg: BX}}, Raw: "MOVB $9, BX"},
		{Op: "MOVB", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 2}}, {Kind: OpReg, Reg: CX}}, Raw: "MOVB 2(BX), CX"},
		{Op: "MOVB", Args: []Operand{{Kind: OpFP, FPOffset: 16}, {Kind: OpReg, Reg: DX}}, Raw: "MOVB arg+16(FP), DX"},
		{Op: "MOVB", Args: []Operand{{Kind: OpSym, Sym: "example.b(SB)"}, {Kind: OpReg, Reg: SI}}, Raw: "MOVB example.b(SB), SI"},
		{Op: "MOVB", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 64}}, Raw: "MOVB AX, ret+64(FP)"},
		{Op: "MOVB", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: DI, Off: 3}}}, Raw: "MOVB AX, 3(DI)"},
		{Op: "MOVB", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "example.b(SB)"}}, Raw: "MOVB AX, example.b(SB)"},
		{Op: "MOVW", Args: []Operand{{Kind: OpImm, Imm: 10}, {Kind: OpReg, Reg: SI}}, Raw: "MOVW $10, SI"},
		{Op: "MOVW", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: SI, Off: 2}}, {Kind: OpReg, Reg: DI}}, Raw: "MOVW 2(SI), DI"},
		{Op: "MOVW", Args: []Operand{{Kind: OpFP, FPOffset: 16}, {Kind: OpReg, Reg: Reg("R8")}}, Raw: "MOVW arg+16(FP), R8"},
		{Op: "MOVW", Args: []Operand{{Kind: OpSym, Sym: "example.w(SB)"}, {Kind: OpReg, Reg: Reg("R9")}}, Raw: "MOVW example.w(SB), R9"},
		{Op: "MOVW", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 56}}, Raw: "MOVW AX, ret+56(FP)"},
		{Op: "MOVW", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: DI, Off: 4}}}, Raw: "MOVW AX, 4(DI)"},
		{Op: "MOVW", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "example.w(SB)"}}, Raw: "MOVW AX, example.w(SB)"},
	} {
		ok, _, err := c.lowerMov(ins.Op, ins)
		check("lowerMov", ins, ok, err)
	}

	if got, err := c.loadXLowI64("X0"); err != nil || got == "" {
		t.Fatalf("loadXLowI64(X0) = (%q, %v)", got, err)
	}
	if got, err := c.loadXLowF64("X0"); err != nil || got == "" {
		t.Fatalf("loadXLowF64(X0) = (%q, %v)", got, err)
	}
	if err := c.storeXLowI64("X1", "77"); err != nil {
		t.Fatalf("storeXLowI64(X1) error = %v", err)
	}
	if err := c.storeXLowF64("X1", "1.500000e+00"); err != nil {
		t.Fatalf("storeXLowF64(X1) error = %v", err)
	}
	if got, err := c.evalF64(Operand{Kind: OpFP, FPOffset: 8}); err != nil || got == "" {
		t.Fatalf("evalF64(double fp) = (%q, %v)", got, err)
	}
	if got, err := c.evalF64(Operand{Kind: OpFP, FPOffset: 16}); err != nil || got == "" {
		t.Fatalf("evalF64(i64 fp) = (%q, %v)", got, err)
	}
	c.fpParams[32] = FrameSlot{Offset: 32, Type: I32, Index: 2, Field: -1}
	if _, err := c.evalF64(Operand{Kind: OpFP, FPOffset: 32}); err == nil {
		t.Fatalf("evalF64(i32 fp) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"fadd double",
		"fsub double",
		"fmul double",
		"fdiv double",
		"fneg double",
		"fcmp ueq double",
		"fcmp ord double",
		"call double @llvm.sqrt.f64",
		"call double @llvm.rint.f64",
		"sitofp i64",
		"sitofp i32",
		"fptosi double",
		"select i1",
		"bitcast i64",
		"bitcast double",
		"store double",
		"store i64",
		"store i32",
		"store i16",
		"store i8",
		`load <16 x i8>, ptr @"example.vec"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64CmpBtCoverage(t *testing.T) {
	sig := FuncSig{
		Name: "example.cmpbt",
		Args: []LLVMType{I64},
		Ret:  Void,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "11"},
		{BX, "12"},
		{CX, "13"},
		{DX, "14"},
		{SI, "15"},
		{DI, "16"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	check := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerCmpBt(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerCmpBt(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	check("CMPB", Instr{Raw: "CMPB $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	check("CMPW", Instr{Raw: "CMPW 4(BX), CX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 4}}, {Kind: OpReg, Reg: CX}}})
	check("CMPL", Instr{Raw: "CMPL arg+0(FP), DI", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: DI}}})
	check("CMPQ", Instr{Raw: "CMPQ example.global(SB), SI", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: SI}}})
	check("TESTB", Instr{Raw: "TESTB AX, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}})
	check("TESTW", Instr{Raw: "TESTW $7, arg+0(FP)", Args: []Operand{{Kind: OpImm, Imm: 7}, {Kind: OpFP, FPOffset: 0}}})
	check("TESTL", Instr{Raw: "TESTL $const, 8(BX)", Args: []Operand{{Kind: OpSym, Sym: "$const"}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}})
	check("TESTQ", Instr{Raw: "TESTQ example.global(SB), DI", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: DI}}})
	check("BTQ", Instr{Raw: "BTQ $3, AX", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: AX}}})
	check("BTSQ", Instr{Raw: "BTSQ DX, AX", Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpReg, Reg: AX}}})
	check("BTRQ", Instr{Raw: "BTRQ $63, AX", Args: []Operand{{Kind: OpImm, Imm: 63}, {Kind: OpReg, Reg: AX}}})
	check("BTRQ", Instr{Raw: "BTRQ DX, (BX)", Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpMem, Mem: MemRef{Base: BX}}}})

	if ok, term, err := c.lowerCmpBt("BAD", Instr{}); ok || term || err != nil {
		t.Fatalf("lowerCmpBt(BAD) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerCmpBt("CMPQ", Instr{Raw: "CMPQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("short CMPQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("TESTQ", Instr{Raw: "TESTQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("short TESTQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTQ", Instr{Raw: "BTQ (AX), BX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: BX}}}); err == nil {
		t.Fatalf("bad BTQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTSQ", Instr{Raw: "BTSQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("short BTSQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTRQ", Instr{Raw: "BTRQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("short BTRQ unexpectedly succeeded")
	}
	if got, err := c.evalIntSized(Operand{Kind: OpSym, Sym: "$const"}, I32); err != nil || got != "0" {
		t.Fatalf("evalIntSized($const) = (%q, %v)", got, err)
	}
	if _, err := c.evalIntSized(Operand{Kind: OpSym, Sym: "bad"}, I32); err == nil {
		t.Fatalf("evalIntSized(bad sym) unexpectedly succeeded")
	}
	if _, err := c.evalIntSized(Operand{Kind: OpIdent, Ident: "label"}, I32); err == nil {
		t.Fatalf("evalIntSized(ident) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"icmp eq i8",
		"icmp slt i16",
		"icmp ult i32",
		"ashr i64",
		"and i64",
		"store i1 false, ptr %flags_cf",
		"lshr i64",
		"shl i64 1",
		"load i64, ptr @\"example.global\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64MovSyscallAndCRC32Coverage(t *testing.T) {
	sig := FuncSig{
		Name: "example.mov",
		Args: []LLVMType{I64},
		Ret:  Void,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0}, {Offset: 16, Type: I16, Index: 1}, {Offset: 24, Type: I8, Index: 2}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "21"},
		{BX, "22"},
		{CX, "23"},
		{DX, "24"},
		{SI, "25"},
		{DI, "26"},
		{Reg("R8"), "27"},
		{Reg("R9"), "28"},
		{Reg("R10"), "29"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	checkMov := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerMov(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerMov(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	checkMov("MOVLQSX", Instr{Raw: "MOVLQSX AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}})
	checkMov("MOVLQSX", Instr{Raw: "MOVLQSX BX, CX", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: CX}}})
	checkMov("MOVLQSX", Instr{Raw: "MOVLQSX arg+0(FP), DX", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: DX}}})
	checkMov("MOVLQSX", Instr{Raw: "MOVLQSX 8(BX), SI", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: SI}}})
	checkMov("MOVLQSX", Instr{Raw: "MOVLQSX example.global(SB), DI", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: DI}}})
	checkMov("MOVWQSX", Instr{Raw: "MOVWQSX 8(BX), SI", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: SI}}})
	b.WriteString("  store i1 true, ptr " + c.flagsSltSlot + "\n")
	checkMov("CMOVQLT", Instr{Raw: "CMOVQLT AX, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}})
	checkMov("MOVB", Instr{Raw: "MOVB $1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}})
	checkMov("MOVBLZX", Instr{Raw: "MOVBLZX 8(BX), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: AX}}})
	checkMov("MOVB", Instr{Raw: "MOVB BX, ret+24(FP)", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpFP, FPOffset: 24}}})
	checkMov("MOVW", Instr{Raw: "MOVW arg+0(FP), 8(BX)", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}})
	checkMov("MOVWLZX", Instr{Raw: "MOVWLZX 8(BX), CX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: CX}}})
	checkMov("MOVWQZX", Instr{Raw: "MOVWQZX 8(BX), DX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: DX}}})
	checkMov("MOVW", Instr{Raw: "MOVW example.global(SB), example.dest(SB)", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVQ", Instr{Raw: "MOVQ example.global(SB), CX", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: CX}}})
	checkMov("MOVQ", Instr{Raw: "MOVQ DX, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpFP, FPOffset: 8}}})
	checkMov("MOVQ", Instr{Raw: "MOVQ $9, 16(BX)", Args: []Operand{{Kind: OpImm, Imm: 9}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 16}}}})
	checkMov("MOVQ", Instr{Raw: "MOVQ SI, example.dest(SB)", Args: []Operand{{Kind: OpReg, Reg: SI}, {Kind: OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVL", Instr{Raw: "MOVL $10, AX", Args: []Operand{{Kind: OpImm, Imm: 10}, {Kind: OpReg, Reg: AX}}})
	checkMov("MOVL", Instr{Raw: "MOVL BX, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpFP, FPOffset: 8}}})
	checkMov("MOVL", Instr{Raw: "MOVL arg+0(FP), 20(BX)", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 20}}}})
	checkMov("MOVL", Instr{Raw: "MOVL 24(BX), example.dest(SB)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 24}}, {Kind: OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVL", Instr{Raw: "MOVL $0xf1, 0xf1", Args: []Operand{{Kind: OpImm, Imm: 0xf1}, {Kind: OpImm, Imm: 0xf1}}})

	if ok, term, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}}); ok || term || err != nil {
		t.Fatalf("lowerMov(vector) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerMov("MOVLQSX", Instr{Raw: "MOVLQSX AX, 8(BX)", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}}); err == nil {
		t.Fatalf("MOVLQSX non-reg dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVB", Instr{Raw: "MOVB label, AX", Args: []Operand{{Kind: OpIdent, Ident: "label"}, {Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("MOVB bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVW", Instr{Raw: "MOVW AX, label", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVW bad sym dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ AX, label", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpLabel, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVQ bad dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVL", Instr{Raw: "MOVL label, AX", Args: []Operand{{Kind: OpIdent, Ident: "label"}, {Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("MOVL bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("MOVQ short arg list unexpectedly succeeded")
	}
	if ok, term, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ Y0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("MOVQ yreg src = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ AX, Y1", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Y1")}}}); ok || term || err != nil {
		t.Fatalf("MOVQ yreg dst = (%v, %v, %v)", ok, term, err)
	}

	cBadReg, _ := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)
	if ok, term, err := cBadReg.lowerMov("MOVB", Instr{Raw: "MOVB BAD, ret+24(FP)", Args: []Operand{{Kind: OpReg, Reg: Reg("BAD")}, {Kind: OpFP, FPOffset: 24}}}); !ok || term || err == nil {
		t.Fatalf("MOVB invalid src reg = (%v, %v, %v), want handled error", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("CMOVQLT", Instr{Raw: "CMOVQLT BAD, BX", Args: []Operand{{Kind: OpReg, Reg: Reg("BAD")}, {Kind: OpReg, Reg: BX}}}); !ok || term || err != nil {
		t.Fatalf("CMOVQLT missing regs = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("MOVQ", Instr{Raw: "MOVQ BAD, 8(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("BAD")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ missing mem base = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("MOVL", Instr{Raw: "MOVL BAD, ret+8(FP)", Args: []Operand{{Kind: OpReg, Reg: Reg("BAD")}, {Kind: OpFP, FPOffset: 8}}}); !ok || term || err != nil {
		t.Fatalf("MOVL missing reg = (%v, %v, %v)", ok, term, err)
	}

	cBadMem, _ := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)
	if ok, term, err := cBadMem.lowerMov("MOVLQSX", Instr{Raw: "MOVLQSX 8(BAD), SI", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: Reg("BAD"), Off: 8}}, {Kind: OpReg, Reg: SI}}}); !ok || term || err != nil {
		t.Fatalf("MOVLQSX bad mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVW", Instr{Raw: "MOVW arg+0(FP), 8(BAD)", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpMem, Mem: MemRef{Base: Reg("BAD"), Off: 8}}}}); !ok || term || err != nil {
		t.Fatalf("MOVW bad dst mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVQ", Instr{Raw: "MOVQ 8(BAD), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: Reg("BAD"), Off: 8}}, {Kind: OpReg, Reg: AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad src mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVL", Instr{Raw: "MOVL 24(BAD), example.dest(SB)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: Reg("BAD"), Off: 24}}, {Kind: OpSym, Sym: "example.dest(SB)"}}}); !ok || term || err != nil {
		t.Fatalf("MOVL bad src mem = (%v, %v, %v)", ok, term, err)
	}

	if ok, term, err := c.lowerMov("MOVLQSX", Instr{Raw: "MOVLQSX broken, AX", Args: []Operand{{Kind: OpSym, Sym: "broken"}, {Kind: OpReg, Reg: AX}}}); !ok || term || err == nil {
		t.Fatalf("MOVLQSX bad sym = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVB", Instr{Raw: "MOVB broken, AX", Args: []Operand{{Kind: OpSym, Sym: "broken"}, {Kind: OpReg, Reg: AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVB bad sym = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ broken, AX", Args: []Operand{{Kind: OpSym, Sym: "broken"}, {Kind: OpReg, Reg: AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad sym src = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", Instr{Raw: "MOVQ AX, broken", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpSym, Sym: "broken"}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad sym dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVL", Instr{Raw: "MOVL broken, AX", Args: []Operand{{Kind: OpSym, Sym: "broken"}, {Kind: OpReg, Reg: AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVL bad sym src = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerMov("MOVL", Instr{Raw: "MOVL AX, label", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpLabel, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVL bad dst unexpectedly succeeded")
	}

	sysc, sysb := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.sys", Ret: Void}, nil)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "1"},
		{DI, "2"},
		{SI, "3"},
		{DX, "4"},
		{Reg("R10"), "5"},
		{Reg("R8"), "6"},
		{Reg("R9"), "7"},
		{BX, "256"},
	} {
		if err := sysc.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("sys storeReg(%s) error = %v", tc.r, err)
		}
	}
	if ok, term, err := sysc.lowerSyscall("INT", Instr{Raw: "INT $3"}); !ok || !term || err != nil {
		t.Fatalf("lowerSyscall(INT) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := sysc.lowerSyscall("SYSCALL", Instr{Raw: "SYSCALL"}); !ok || term || err != nil {
		t.Fatalf("lowerSyscall(SYSCALL) = (%v, %v, %v)", ok, term, err)
	}
	for _, tc := range []Instr{
		{Op: "CRC32B", Raw: "CRC32B 8(BX), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: AX}}},
		{Op: "CRC32W", Raw: "CRC32W 8(BX), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: AX}}},
		{Op: "CRC32L", Raw: "CRC32L 8(BX), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: AX}}},
		{Op: "CRC32Q", Raw: "CRC32Q 8(BX), AX", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: AX}}},
	} {
		if ok, term, err := sysc.lowerCrc32(tc.Op, tc); !ok || term || err != nil {
			t.Fatalf("lowerCrc32(%s) = (%v, %v, %v)", tc.Op, ok, term, err)
		}
	}
	if _, _, err := sysc.lowerSyscall("SYSCALL", Instr{Raw: "SYSCALL AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("SYSCALL with args unexpectedly succeeded")
	}
	if ok, term, err := sysc.lowerSyscall("BAD", Instr{}); ok || term || err != nil {
		t.Fatalf("lowerSyscall(BAD) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := sysc.lowerCrc32("CRC32B", Instr{Raw: "CRC32B $1, BX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: BX}}}); err == nil {
		t.Fatalf("bad CRC32B unexpectedly succeeded")
	}
	if ok, term, err := sysc.lowerCrc32("BAD", Instr{}); ok || term || err != nil {
		t.Fatalf("lowerCrc32(BAD) = (%v, %v, %v)", ok, term, err)
	}

	out := b.String() + sysb.String()
	for _, want := range []string{
		"sext i32",
		"sext i16",
		"select i1 %t",
		"zext i8",
		"store i16",
		"store i32",
		"@syscall(i64",
		"@cliteErrno()",
		"@llvm.x86.sse42.crc32.32.8",
		"@llvm.x86.sse42.crc32.32.16",
		"@llvm.x86.sse42.crc32.32.32",
		"@llvm.x86.sse42.crc32.64.64",
		"unreachable",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64BranchCoverageDeep(t *testing.T) {
	fn := Func{Instrs: []Instr{{Op: "NOP"}, {Op: "NOP"}, {Op: "NOP"}, {Op: "NOP"}}}
	sigs := map[string]FuncSig{
		"example.tail": {Name: "example.tail", Args: []LLVMType{I64}, Ret: I64},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Name: "example.branch", Args: []LLVMType{I64}, Ret: I64}, sigs)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "31"},
		{BX, "32"},
		{CX, "33"},
		{DX, "34"},
		{DI, "35"},
		{SI, "36"},
		{Reg("R8"), "37"},
		{Reg("R9"), "38"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	c.blocks = []amd64Block{{name: "entry"}, {name: "fall"}, {name: "V1"}, {name: "tail"}}
	c.blockBase = []int{0, 1, 2, 3}
	c.blockByIdx = map[int]int{0: 0, 1: 1, 2: 2, 3: 3}
	c.setCmpFlags("1", "2")

	emitBr := func(target string) { b.WriteString("  br label %" + amd64LLVMBlockName(target) + "\n") }
	emitCondBr := func(cond string, target string, fall string) error {
		b.WriteString("  br i1 " + cond + ", label %" + amd64LLVMBlockName(target) + ", label %" + amd64LLVMBlockName(fall) + "\n")
		return nil
	}
	for _, tc := range []struct {
		op  Op
		ins Instr
	}{
		{"JE", Instr{Raw: "JE V1", Args: []Operand{{Kind: OpIdent, Ident: "V1"}}}},
		{"JNE", Instr{Raw: "JNE tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JL", Instr{Raw: "JL V1<>(SB)", Args: []Operand{{Kind: OpSym, Sym: "V1<>(SB)"}}}},
		{"JGE", Instr{Raw: "JGE 2(PC)", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: PC, Off: 2}}}}},
		{"JS", Instr{Raw: "JS tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JNS", Instr{Raw: "JNS V1", Args: []Operand{{Kind: OpIdent, Ident: "V1"}}}},
		{"JLE", Instr{Raw: "JLE tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JG", Instr{Raw: "JG V1", Args: []Operand{{Kind: OpIdent, Ident: "V1"}}}},
		{"JB", Instr{Raw: "JB tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JNC", Instr{Raw: "JNC V1", Args: []Operand{{Kind: OpIdent, Ident: "V1"}}}},
		{"JAE", Instr{Raw: "JAE tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JBE", Instr{Raw: "JBE V1", Args: []Operand{{Kind: OpIdent, Ident: "V1"}}}},
		{"JNA", Instr{Raw: "JNA tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JA", Instr{Raw: "JA tail", Args: []Operand{{Kind: OpIdent, Ident: "tail"}}}},
		{"JMP", Instr{Raw: "JMP V1", Args: []Operand{{Kind: OpReg, Reg: Reg("V1")}}}},
		{"JMP", Instr{Raw: "JMP tail(SB)", Args: []Operand{{Kind: OpSym, Sym: "tail(SB)"}}}},
	} {
		if ok, term, err := c.lowerBranch(0, 0, tc.op, tc.ins, emitBr, emitCondBr); !ok || !term || err != nil {
			t.Fatalf("lowerBranch(%s %q) = (%v, %v, %v)", tc.op, tc.ins.Raw, ok, term, err)
		}
	}
	if _, _, err := c.lowerBranch(0, 0, "CALL", Instr{Raw: "CALL $1", Args: []Operand{{Kind: OpImm, Imm: 1}}}, emitBr, emitCondBr); err == nil {
		t.Fatalf("CALL imm unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, 0, "JMP", Instr{Raw: "JMP $1", Args: []Operand{{Kind: OpImm, Imm: 1}}}, emitBr, emitCondBr); err == nil {
		t.Fatalf("JMP imm unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, 0, "JEQ", Instr{Raw: "JEQ", Args: nil}, emitBr, emitCondBr); err == nil {
		t.Fatalf("JEQ without target unexpectedly succeeded")
	}
	oneBlock, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.one", Ret: Void}, nil)
	oneBlock.blocks = []amd64Block{{name: "solo"}}
	oneBlock.blockBase = []int{0}
	oneBlock.blockByIdx = map[int]int{0: 0}
	oneBlock.setCmpFlags("1", "1")
	if _, _, err := oneBlock.lowerBranch(0, 0, "JEQ", Instr{Raw: "JEQ solo", Args: []Operand{{Kind: OpIdent, Ident: "solo"}}}, emitBr, emitCondBr); err == nil {
		t.Fatalf("JEQ without fallthrough unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"xor i1",
		"or i1",
		"call i64 @\"example.tail\"",
		"ret i64",
		"br label %V1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64FPExtraCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}},
		},
	}
	sig := FuncSig{
		Name: "example.fpextra",
		Args: []LLVMType{I64, LLVMType("double")},
		Ret:  Void,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0},
				{Offset: 8, Type: LLVMType("double"), Index: 1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "51"},
		{BX, "52"},
		{Reg("X0"), "<16 x i8> zeroinitializer"},
		{Reg("X1"), "<16 x i8> zeroinitializer"},
		{Reg("Y0"), "<32 x i8> zeroinitializer"},
		{Reg("Y1"), "<32 x i8> zeroinitializer"},
		{Reg("Z0"), "<64 x i8> zeroinitializer"},
		{Reg("Z1"), "<64 x i8> zeroinitializer"},
	} {
		switch {
		case strings.HasPrefix(string(tc.r), "X"):
			if err := c.storeX(tc.r, tc.v); err != nil {
				t.Fatalf("storeX(%s) error = %v", tc.r, err)
			}
		case strings.HasPrefix(string(tc.r), "Y"):
			if err := c.storeY(tc.r, tc.v); err != nil {
				t.Fatalf("storeY(%s) error = %v", tc.r, err)
			}
		case strings.HasPrefix(string(tc.r), "Z"):
			if err := c.storeZ(tc.r, tc.v); err != nil {
				t.Fatalf("storeZ(%s) error = %v", tc.r, err)
			}
		default:
			if err := c.storeReg(tc.r, tc.v); err != nil {
				t.Fatalf("storeReg(%s) error = %v", tc.r, err)
			}
		}
	}

	if got, err := c.loadYVecOperand(Operand{Kind: OpReg, Reg: Reg("Y0")}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(reg) = (%q, %v)", got, err)
	}
	if got, err := c.loadYVecOperand(Operand{Kind: OpMem, Mem: MemRef{Base: AX, Off: 8}}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(mem) = (%q, %v)", got, err)
	}
	if got, err := c.loadYVecOperand(Operand{Kind: OpSym, Sym: "example.vec32(SB)"}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(sym) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(Operand{Kind: OpReg, Reg: Reg("Z0")}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(reg) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(Operand{Kind: OpMem, Mem: MemRef{Base: AX, Off: 16}}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(mem) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(Operand{Kind: OpSym, Sym: "example.vec64(SB)"}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(sym) = (%q, %v)", got, err)
	}

	check := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerFP(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerFP(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}
	for _, pred := range []int64{0, 1, 2, 3, 4, 6} {
		check("CMPSD", Instr{Raw: "CMPSD X0, X1, $pred", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpImm, Imm: pred}}})
	}
	check("VADDSD", Instr{Raw: "VADDSD X0, X1, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("VFMADD213SD", Instr{Raw: "VFMADD213SD X0, X1, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("VFNMADD231SD", Instr{Raw: "VFNMADD231SD X0, X1, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: Reg("X0")}}})

	if ok, term, err := c.lowerFP("MOVAPD", Instr{Raw: "MOVAPD X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("MOVAPD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerFP("MOVSD", Instr{Raw: "MOVSD X0, label", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("MOVSD bad dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerFP("ADDSD", Instr{Raw: "ADDSD X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("ADDSD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerFP("SQRTSD", Instr{Raw: "SQRTSD X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("SQRTSD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerFP("COMISD", Instr{Raw: "COMISD X0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}}}); err == nil {
		t.Fatalf("COMISD short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerFP("CMPSD", Instr{Raw: "CMPSD X0, X1, bad", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpSym, Sym: "bad"}}}); err == nil {
		t.Fatalf("CMPSD bad sym predicate unexpectedly succeeded")
	}
	if _, _, err := c.lowerFP("CMPSD", Instr{Raw: "CMPSD X0, X1, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("CMPSD reg predicate unexpectedly succeeded")
	}
	if ok, term, err := c.lowerFP("CVTSQ2SD", Instr{Raw: "CVTSQ2SD AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("CVTSQ2SD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerFP("CVTSL2SD", Instr{Raw: "CVTSL2SD AX, AX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: AX}}}); ok || term || err != nil {
		t.Fatalf("CVTSL2SD non-X dst = (%v, %v, %v)", ok, term, err)
	}

	out := b.String()
	for _, want := range []string{
		"load <32 x i8>",
		"load <64 x i8>",
		"fcmp oeq double",
		"fcmp olt double",
		"fcmp ole double",
		"fcmp uno double",
		"fcmp une double",
		"fcmp ugt double",
		"fadd double",
		"call double @llvm.fma.f64",
		"fneg double",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64VectorAliasAndErrorCoverage(t *testing.T) {
	fn := Func{
		Instrs: []Instr{
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("X2")}, {Kind: OpReg, Reg: Reg("X3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Y2")}, {Kind: OpReg, Reg: Reg("Y3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("Z2")}, {Kind: OpReg, Reg: Reg("Z3")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K2")}}},
			{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: Reg("K3")}, {Kind: OpReg, Reg: Reg("K4")}}},
		},
	}
	sig := FuncSig{
		Name: "example.vecalias",
		Args: []LLVMType{I64},
		Ret:  Void,
		Frame: FrameLayout{
			Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "61"},
		{BX, "62"},
		{CX, "63"},
		{DX, "64"},
		{Reg("K1"), "1"},
		{Reg("K2"), "2"},
	} {
		if strings.HasPrefix(string(tc.r), "K") {
			if err := c.storeK(tc.r, tc.v); err != nil {
				t.Fatalf("storeK(%s) error = %v", tc.r, err)
			}
			continue
		}
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	check := func(op Op, ins Instr) {
		t.Helper()
		if ok, term, err := c.lowerVec(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerVec(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	check("VZEROUPPER", Instr{Raw: "VZEROUPPER"})
	check("VZEROALL", Instr{Raw: "VZEROALL"})
	check("VMOVDQA", Instr{Raw: "VMOVDQA Y0, Y1", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	check("VMOVDQA64", Instr{Raw: "VMOVDQA64 Z0, Z1", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}})
	check("VPERM2F128", Instr{Raw: "VPERM2F128 $1, Y0, Y1, Y2", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	check("VMOVAPS", Instr{Raw: "VMOVAPS Z0, Z1", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}}})
	check("VMOVAPD", Instr{Raw: "VMOVAPD Y0, Y1", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}})
	check("VPXORQ", Instr{Raw: "VPXORQ Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	check("VPANDQ", Instr{Raw: "VPANDQ Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	check("VPORQ", Instr{Raw: "VPORQ Y0, Y1, Y2", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("Y2")}}})
	check("MOVUPS", Instr{Raw: "MOVUPS 8(BX), X0", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("MOVAPS", Instr{Raw: "MOVAPS X0, 16(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 16}}}})
	check("MOVO", Instr{Raw: "MOVO X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}})
	check("MOVQ", Instr{Raw: "MOVQ arg+0(FP), X0", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("MOVQ", Instr{Raw: "MOVQ 24(BX), X1", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 24}}, {Kind: OpReg, Reg: Reg("X1")}}})
	check("MOVQ", Instr{Raw: "MOVQ example.global(SB), X2", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: Reg("X2")}}})
	check("MOVQ", Instr{Raw: "MOVQ X0, 32(BX)", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 32}}}})
	check("MOVOU", Instr{Raw: "MOVOU example.global(SB), X0", Args: []Operand{{Kind: OpSym, Sym: "example.global(SB)"}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("MOVOA", Instr{Raw: "MOVOA X0, example.out(SB)", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpSym, Sym: "example.out(SB)"}}})
	check("KMOVB", Instr{Raw: "KMOVB 8(BX), K1", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: Reg("K1")}}})
	check("KMOVD", Instr{Raw: "KMOVD K1, K7", Args: []Operand{{Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K7")}}})
	check("VMOVDQU64", Instr{Raw: "VMOVDQU64 example.zin(SB), Z0", Args: []Operand{{Kind: OpSym, Sym: "example.zin(SB)"}, {Kind: OpReg, Reg: Reg("Z0")}}})
	check("VMOVDQU64", Instr{Raw: "VMOVDQU64 Z0, example.zout(SB)", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpSym, Sym: "example.zout(SB)"}}})
	check("VMOVDQU", Instr{Raw: "VMOVDQU example.yin(SB), Y0", Args: []Operand{{Kind: OpSym, Sym: "example.yin(SB)"}, {Kind: OpReg, Reg: Reg("Y0")}}})
	check("VMOVDQU", Instr{Raw: "VMOVDQU Y0, example.yout(SB)", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpSym, Sym: "example.yout(SB)"}}})
	check("VMOVDQU", Instr{Raw: "VMOVDQU example.xin(SB), X0", Args: []Operand{{Kind: OpSym, Sym: "example.xin(SB)"}, {Kind: OpReg, Reg: Reg("X0")}}})
	check("VMOVDQU", Instr{Raw: "VMOVDQU X0, example.xout(SB)", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpSym, Sym: "example.xout(SB)"}}})
	check("PEXTRB", Instr{Raw: "PEXTRB $1, X1, example.byteout(SB)", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X1")}, {Kind: OpSym, Sym: "example.byteout(SB)"}}})

	if _, _, err := c.lowerVec("MOVL", Instr{Raw: "MOVL label, X0", Args: []Operand{{Kind: OpIdent, Ident: "label"}, {Kind: OpReg, Reg: Reg("X0")}}}); err == nil {
		t.Fatalf("MOVL bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("MOVQ", Instr{Raw: "MOVQ label, X0", Args: []Operand{{Kind: OpIdent, Ident: "label"}, {Kind: OpReg, Reg: Reg("X0")}}}); err == nil {
		t.Fatalf("MOVQ bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("MOVQ", Instr{Raw: "MOVQ X0, label", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("MOVQ bad dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("KXORQ", Instr{Raw: "KXORQ AX, K1, K2", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("K2")}}}); !ok || term || err == nil {
		t.Fatalf("KXORQ non-k src = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("KMOVB", Instr{Raw: "KMOVB AX", Args: []Operand{{Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("KMOVB short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("KMOVB", Instr{Raw: "KMOVB label, AX", Args: []Operand{{Kind: OpIdent, Ident: "label"}, {Kind: OpReg, Reg: AX}}}); err == nil {
		t.Fatalf("KMOVB bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("KMOVB", Instr{Raw: "KMOVB AX, label", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("KMOVB bad dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMB", Instr{Raw: "VPERMB Z0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}}}); err == nil {
		t.Fatalf("VPERMB short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMB", Instr{Raw: "VPERMB Z0, Z1, 7", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpImm, Imm: 7}}}); err == nil {
		t.Fatalf("VPERMB non-reg dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMB", Instr{Raw: "VPERMB Z0, Z1, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Y0")}}}); !ok || term || err == nil {
		t.Fatalf("VPERMB wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMB", Instr{Raw: "VPERMB Z0, Z1, 7, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpImm, Imm: 7}, {Kind: OpReg, Reg: Reg("Z2")}}}); err == nil {
		t.Fatalf("VPERMB non-reg mask unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMB", Instr{Raw: "VPERMB Z0, Z1, AX, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Z2")}}}); !ok || term || err == nil {
		t.Fatalf("VPERMB wrong mask reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VGF2P8AFFINEQB", Instr{Raw: "VGF2P8AFFINEQB Z0, Z1, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}}); err == nil {
		t.Fatalf("VGF2P8AFFINEQB short form unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VGF2P8AFFINEQB", Instr{Raw: "VGF2P8AFFINEQB $1, Z0, Z1, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Y0")}}}); !ok || term || err == nil {
		t.Fatalf("VGF2P8AFFINEQB wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMI2B", Instr{Raw: "VPERMI2B Z0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}}}); err == nil {
		t.Fatalf("VPERMI2B short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, 7", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpImm, Imm: 7}}}); err == nil {
		t.Fatalf("VPERMI2B non-reg dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Y0")}}}); !ok || term || err == nil {
		t.Fatalf("VPERMI2B wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, 7, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpImm, Imm: 7}, {Kind: OpReg, Reg: Reg("Z2")}}}); err == nil {
		t.Fatalf("VPERMI2B non-reg mask unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMI2B", Instr{Raw: "VPERMI2B Z0, Z1, AX, Z2", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Z2")}}}); !ok || term || err == nil {
		t.Fatalf("VPERMI2B wrong mask reg = (%v, %v, %v)", ok, term, err)
	}
	for _, tc := range []struct {
		op          Op
		ins         Instr
		want        string
		wantHandled bool
	}{
		{"VPOPCNTB", Instr{Raw: "VPOPCNTB Z0, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst", true},
		{"VPCMPUQ", Instr{Raw: "VPCMPUQ $3, Z0, Z1, K1", Args: []Operand{{Kind: OpImm, Imm: 3}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("K1")}}}, "bad imm", true},
		{"VPCMPUQ", Instr{Raw: "VPCMPUQ $1, Z0, Z1, AX", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: AX}}}, "wrong dst reg", false},
		{"VPCOMPRESSQ", Instr{Raw: "VPCOMPRESSQ Z0, AX, Z1", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Z1")}}}, "wrong mask", true},
		{"VPCOMPRESSQ", Instr{Raw: "VPCOMPRESSQ Z0, K1, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("K1")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst", true},
		{"VPXORQ", Instr{Raw: "VPXORQ Z0, Z1, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong z dst", true},
		{"VPSHUFB", Instr{Raw: "VPSHUFB Y0, Y1, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: AX}}}, "wrong dst", false},
		{"VPSHUFD", Instr{Raw: "VPSHUFD $1, X0, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong src class", true},
		{"VPSLLD", Instr{Raw: "VPSLLD Y0, Y1", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}}, "short form", true},
		{"VPERM2I128", Instr{Raw: "VPERM2I128 $1, Y0, Y1, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong dst", true},
		{"VINSERTI128", Instr{Raw: "VINSERTI128 $1, X0, Y0, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X1")}}}, "wrong dst", false},
		{"VMOVNTDQ", Instr{Raw: "VMOVNTDQ Y0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: AX}}}, "bad dst", true},
		{"AESKEYGENASSIST", Instr{Raw: "AESKEYGENASSIST X0, X1", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}}, "missing imm", true},
		{"VPTEST", Instr{Raw: "VPTEST X0, Y0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong src class", true},
		{"PCMPESTRI", Instr{Raw: "PCMPESTRI $-1, 8(BX), X0", Args: []Operand{{Kind: OpImm, Imm: -1}, {Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, {Kind: OpReg, Reg: Reg("X0")}}}, "invalid imm", true},
		{"PCMPESTRI", Instr{Raw: "PCMPESTRI $0x0c, AX, X0", Args: []Operand{{Kind: OpImm, Imm: 0x0c}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}}, "bad mem operand", true},
		{"VPBLENDD", Instr{Raw: "VPBLENDD $1, Y0, Y1, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong dst", false},
		{"VPBROADCASTB", Instr{Raw: "VPBROADCASTB Y0, Y1", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("Y1")}}}, "wrong src", false},
		{"VPSRLDQ", Instr{Raw: "VPSRLDQ $2, X0, Y0", Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong src class", true},
		{"PUNPCKLBW", Instr{Raw: "PUNPCKLBW Y0, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong src class", false},
		{"PSHUFHW", Instr{Raw: "PSHUFHW $1, X0, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst", true},
		{"SHUFPS", Instr{Raw: "SHUFPS $1, X0, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst", false},
		{"MOVOU", Instr{Raw: "MOVOU AX, X0", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong src class", true},
		{"MOVOU", Instr{Raw: "MOVOU X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}}, "wrong dst class", false},
		{"PXOR", Instr{Raw: "PXOR X0", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}}}, "short form", true},
		{"PADDL", Instr{Raw: "PADDL X0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}}}, "wrong dst class", false},
		{"PSLLL", Instr{Raw: "PSLLL AX, X0", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}}, "non-imm shift", true},
		{"PCMPEQL", Instr{Raw: "PCMPEQL Y0, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong src class", false},
		{"VPCLMULQDQ", Instr{Raw: "VPCLMULQDQ $1, Z0, Z1, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong dst class", true},
		{"VPTERNLOGD", Instr{Raw: "VPTERNLOGD $0x100, Z0, Z1, Z2", Args: []Operand{{Kind: OpImm, Imm: 0x100}, {Kind: OpReg, Reg: Reg("Z0")}, {Kind: OpReg, Reg: Reg("Z1")}, {Kind: OpReg, Reg: Reg("Z2")}}}, "out-of-range imm", true},
		{"VEXTRACTF32X4", Instr{Raw: "VEXTRACTF32X4 $1, X0, X1", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}}, "wrong src class", false},
		{"PCLMULQDQ", Instr{Raw: "PCLMULQDQ AX, X0, X1", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: Reg("X1")}}}, "missing imm", true},
		{"PCMPEQB", Instr{Raw: "PCMPEQB Y0, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong src class", false},
		{"PMOVMSKB", Instr{Raw: "PMOVMSKB Y0, AX", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: AX}}}, "wrong src class", false},
		{"PSHUFB", Instr{Raw: "PSHUFB Y0, X0", Args: []Operand{{Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong mask class", true},
		{"PINSRQ", Instr{Raw: "PINSRQ AX, X0", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}}, "short form", true},
		{"PINSRD", Instr{Raw: "PINSRD $1, AX, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst class", true},
		{"PINSRW", Instr{Raw: "PINSRW $1, AX, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst class", true},
		{"PINSRB", Instr{Raw: "PINSRB $1, AX, Y0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("Y0")}}}, "wrong dst class", true},
		{"PEXTRB", Instr{Raw: "PEXTRB AX, X0, BX", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: BX}}}, "missing imm", true},
		{"PALIGNR", Instr{Raw: "PALIGNR $1, Y0, X0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("Y0")}, {Kind: OpReg, Reg: Reg("X0")}}}, "wrong src class", true},
		{"PSRLDQ", Instr{Raw: "PSRLDQ $128, X0", Args: []Operand{{Kind: OpImm, Imm: 128}, {Kind: OpReg, Reg: Reg("X0")}}}, "invalid imm", true},
		{"PSLLDQ", Instr{Raw: "PSLLDQ $128, X0", Args: []Operand{{Kind: OpImm, Imm: 128}, {Kind: OpReg, Reg: Reg("X0")}}}, "invalid imm", true},
		{"PSRLQ", Instr{Raw: "PSRLQ AX, X0", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: Reg("X0")}}}, "non-imm shift", true},
		{"PEXTRD", Instr{Raw: "PEXTRD $1, X0, label", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: Reg("X0")}, {Kind: OpIdent, Ident: "label"}}}, "bad dst kind", true},
	} {
		ok, term, err := c.lowerVec(tc.op, tc.ins)
		if tc.wantHandled {
			if !ok || err == nil {
				t.Fatalf("%s %s = (%v, %v, %v), want handled error", tc.op, tc.want, ok, term, err)
			}
			continue
		}
		if ok || err != nil {
			t.Fatalf("%s %s = (%v, %v, %v), want unhandled failure", tc.op, tc.want, ok, term, err)
		}
	}

	out := b.String()
	for _, want := range []string{
		"load i64, ptr @\"example.global\"",
		"load i8, ptr",
		"and i64",
		"store i64",
		"zext i8",
		"shufflevector <4 x i64>",
		"load <64 x i8>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64RejectedLegacyVectorDestinationDoesNotMutateIR(t *testing.T) {
	for _, test := range []struct {
		op      Op
		handled bool
	}{
		{op: "PSUBUSB"},
		{op: "PABSD"},
		{op: "PTEST", handled: true},
	} {
		t.Run(string(test.op), func(t *testing.T) {
			ins := Instr{
				Op: test.op, Raw: string(test.op) + " X0, AX",
				Args: []Operand{{Kind: OpReg, Reg: Reg("X0")}, {Kind: OpReg, Reg: AX}},
			}
			c, b := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			beforeIR, beforeTmp := b.String(), c.tmp
			ok, term, err := c.lowerVec(test.op, ins)
			if test.handled {
				if !ok || term || err == nil {
					t.Fatalf("lowerVec(%s) = (%v, %v, %v), want handled rejection", test.op, ok, term, err)
				}
			} else if ok || term || err != nil {
				t.Fatalf("lowerVec(%s) = (%v, %v, %v), want unhandled rejection", test.op, ok, term, err)
			}
			if got := b.String(); got != beforeIR {
				t.Fatalf("lowerVec(%s) emitted IR before rejecting destination:\n%s", test.op, strings.TrimPrefix(got, beforeIR))
			}
			if c.tmp != beforeTmp {
				t.Fatalf("lowerVec(%s) advanced temporary counter from %d to %d", test.op, beforeTmp, c.tmp)
			}
		})
	}
}

func TestAMD64CtxAliasAndFPFallbackCoverage(t *testing.T) {
	sig := FuncSig{
		Name: "example.ctxfallback",
		Ret:  Void,
		Frame: FrameLayout{
			Results: []FrameSlot{
				{Offset: 8, Type: I1, Index: 0},
				{Offset: 16, Type: I8, Index: 1},
				{Offset: 24, Type: I16, Index: 2},
				{Offset: 32, Type: I32, Index: 3},
				{Offset: 40, Type: I64, Index: 4},
				{Offset: 48, Type: Ptr, Index: 5},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)

	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AX, "255"},
		{BX, "511"},
		{CX, "1023"},
		{DX, "2047"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	for _, tc := range []struct {
		r  Reg
		ty LLVMType
		v  string
	}{
		{BX, I8, "37"},
		{CX, I16, "38"},
		{DX, I32, "39"},
	} {
		if err := c.storeRegSized(tc.r, tc.ty, tc.v); err != nil {
			t.Fatalf("storeRegSized(%s, %s) error = %v", tc.r, tc.ty, err)
		}
	}
	for _, r := range []Reg{AL, AH, BL, BH, CL, CH, DL, DH, BPB, SIB, DIB, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B} {
		if got, err := c.loadReg(r); err != nil || got == "" {
			t.Fatalf("loadReg(%s) = (%q, %v)", r, got, err)
		}
	}
	if got, err := c.loadReg(Reg("MISSING")); err != nil || got != "0" {
		t.Fatalf("loadReg(MISSING) = (%q, %v)", got, err)
	}
	for _, tc := range []struct {
		r Reg
		v string
	}{
		{AL, "17"},
		{AH, "33"},
		{BL, "18"},
		{BH, "34"},
		{CL, "19"},
		{CH, "35"},
		{DL, "20"},
		{DH, "36"},
		{BPB, "22"},
		{SIB, "23"},
		{DIB, "24"},
		{R8B, "25"},
		{R9B, "26"},
		{R10B, "27"},
		{R11B, "28"},
		{R12B, "29"},
		{R13B, "30"},
		{R14B, "31"},
		{R15B, "32"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	if err := c.storeReg(Reg("MISSING"), "21"); err != nil {
		t.Fatalf("storeReg(MISSING) error = %v", err)
	}

	for _, tc := range []struct {
		off int64
		ty  LLVMType
		val string
	}{
		{8, I1, "1"},
		{16, I8, "2"},
		{24, I16, "3"},
		{32, I32, "4"},
		{40, I64, "5"},
		{48, I64, "6"},
	} {
		if err := c.storeFPResult(tc.off, tc.ty, tc.val); err != nil {
			t.Fatalf("storeFPResult(%d, %s) error = %v", tc.off, tc.ty, err)
		}
	}
	for _, tc := range []struct {
		off int64
		ty  LLVMType
		val string
	}{
		{8, I64, "7"},
		{32, I16, "8"},
		{40, LLVMType("double"), "%dbl"},
	} {
		if err := c.storeFPResult(tc.off, tc.ty, tc.val); err != nil {
			t.Fatalf("storeFPResult(extra %d, %s) error = %v", tc.off, tc.ty, err)
		}
	}
	if err := c.storeFPResult(40, Ptr, "%arg0"); err != nil {
		t.Fatalf("storeFPResult(ptr->i64) error = %v", err)
	}
	for _, off := range []int64{8, 16, 24, 32, 40, 48, 56} {
		if got, err := c.evalFPToI64(off); err != nil || got == "" {
			t.Fatalf("evalFPToI64(%d) = (%q, %v)", off, got, err)
		}
	}

	out := b.String()
	for _, want := range []string{
		"and i64",
		"lshr i64",
		"shl i64",
		"or i64",
		"zext i1",
		"zext i8",
		"zext i16",
		"zext i32",
		"ptrtoint ptr",
		"inttoptr i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in ctx fallback output:\n%s", want, out)
		}
	}
}
