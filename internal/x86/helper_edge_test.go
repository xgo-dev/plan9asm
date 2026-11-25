package x86

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	"testing"
)

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

func newAMD64CtxWithFuncForTest(t *testing.T, fn asm.Func, sig asm.FuncSig, sigs map[string]asm.FuncSig) (*amd64Ctx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]asm.FuncSig{}
	}
	var b strings.Builder
	c := newAMD64Ctx(&b, fn, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatalf("emitEntryAllocas() error = %v", err)
	}
	return c, &b
}

func TestAMD64CtxHelperEdges(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y2")}, {Kind: asm.OpReg, Reg: asm.Reg("Y3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z4")}, {Kind: asm.OpReg, Reg: asm.Reg("Z5")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("K2")}}},
		},
	}
	sig := asm.FuncSig{
		Name: "example.ctx",
		Args: []asm.LLVMType{asm.Ptr, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64, asm.LLVMType("double"), asm.LLVMType("float")},
		Ret:  asm.LLVMType("{i32, ptr, double, float, i16}"),
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: asm.I1, Index: 1, Field: -1},
				{Offset: 16, Type: asm.I8, Index: 2, Field: -1},
				{Offset: 24, Type: asm.I16, Index: 3, Field: -1},
				{Offset: 32, Type: asm.I32, Index: 4, Field: -1},
				{Offset: 40, Type: asm.I64, Index: 5, Field: -1},
				{Offset: 48, Type: asm.LLVMType("double"), Index: 6, Field: -1},
				{Offset: 56, Type: asm.LLVMType("float"), Index: 7, Field: -1},
			},
			Results: []asm.FrameSlot{
				{Offset: 80, Type: asm.I32, Index: 0, Field: -1},
				{Offset: 88, Type: asm.Ptr, Index: 1, Field: -1},
				{Offset: 96, Type: asm.LLVMType("double"), Index: 2, Field: -1},
				{Offset: 104, Type: asm.LLVMType("float"), Index: 3, Field: -1},
				{Offset: 112, Type: asm.I16, Index: 4, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)

	for _, ty := range []asm.LLVMType{asm.Ptr, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64} {
		if got, ok, err := amd64ValueAsI64(c, ty, "%v"); err != nil || !ok || got == "" {
			t.Fatalf("amd64ValueAsI64(%s) = (%q, %v, %v)", ty, got, ok, err)
		}
	}
	if got, ok, err := amd64ValueAsI64(c, asm.LLVMType("v2i64"), "%v"); err != nil || ok || got != "" {
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

		if slot, ok := c.fpParam(32); !ok || slot.Type != asm.I32 {
			t.Fatalf("fpParam(32) = (%#v, %v)", slot, ok)
		}
		if _, ok := c.fpParam(999); ok {
			t.Fatalf("fpParam(999) unexpectedly succeeded")
		}
		if alloca, ty, ok := c.fpResultAlloca(80); !ok || alloca == "" || ty != asm.I32 {
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
		c.fpParams[64] = asm.FrameSlot{Offset: 64, Type: asm.LLVMType("v4i32"), Index: 0}
		if _, err := c.evalFPToI64(64); err == nil {
			t.Fatalf("evalFPToI64(unsupported type) unexpectedly succeeded")
		}
		c.fpParams[72] = asm.FrameSlot{Offset: 72, Type: asm.I64, Index: 99}
		if _, err := c.evalFPToI64(72); err == nil {
			t.Fatalf("evalFPToI64(invalid index) unexpectedly succeeded")
		}

		if err := c.storeFPResult(80, asm.I64, "11"); err != nil {
			t.Fatalf("storeFPResult(i64->i32) error = %v", err)
		}
		if err := c.storeFPResult(88, asm.I64, "12"); err != nil {
			t.Fatalf("storeFPResult(i64->ptr) error = %v", err)
		}
		if err := c.storeFPResult(96, asm.I64, "13"); err != nil {
			t.Fatalf("storeFPResult(i64->double) error = %v", err)
		}
		if err := c.storeFPResult(104, asm.LLVMType("float"), "%f"); err != nil {
			t.Fatalf("storeFPResult(float->float) error = %v", err)
		}
		if err := c.storeFPResult(112, asm.I8, "15"); err != nil {
			t.Fatalf("storeFPResult(i8->i16) error = %v", err)
		}
		if err := c.storeFPResult(96, asm.LLVMType("double"), "%x"); err != nil {
			t.Fatalf("storeFPResult(double->double) error = %v", err)
		}
		if err := c.storeFPResult(80, asm.Ptr, "%x"); err == nil {
			t.Fatalf("storeFPResult(ptr->i32) unexpectedly succeeded")
		}

		if got, err := c.loadFPResult(asm.FrameSlot{Index: 0, Type: asm.I32}); err != nil || got == "" {
			t.Fatalf("loadFPResult() = (%q, %v)", got, err)
		}
		if _, err := c.loadFPResult(asm.FrameSlot{Index: 99, Type: asm.I32}); err == nil {
			t.Fatalf("loadFPResult(missing) unexpectedly succeeded")
		}
	})

	t.Run("ReturnHelpers", func(t *testing.T) {
		if !isAMD64FloatRetTy(asm.LLVMType("double")) || !isAMD64FloatRetTy(asm.LLVMType("float")) || isAMD64FloatRetTy(asm.I64) {
			t.Fatalf("isAMD64FloatRetTy() mismatch")
		}
		if got, ok := c.retIntRegByOrd(1); !ok || got != asm.BX {
			t.Fatalf("retIntRegByOrd(1) = (%q, %v)", got, ok)
		}
		if _, ok := c.retIntRegByOrd(-1); ok {
			t.Fatalf("retIntRegByOrd(-1) unexpectedly succeeded")
		}
	})

	if err := c.storeReg(asm.AX, "21"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	if err := c.storeReg(asm.BX, "22"); err != nil {
		t.Fatalf("storeReg(BX) error = %v", err)
	}
	if err := c.storeX("X0", "<16 x i8> zeroinitializer"); err != nil {
		t.Fatalf("storeX(X0) error = %v", err)
	}
	for _, tc := range []struct {
		ord int
		ty  asm.LLVMType
	}{
		{0, asm.I64},
		{1, asm.I32},
		{0, asm.I16},
		{0, asm.I8},
		{0, asm.I1},
		{0, asm.Ptr},
		{0, asm.LLVMType("double")},
		{0, asm.LLVMType("float")},
	} {
		if got, err := c.loadRetIntRegTyped(tc.ord, tc.ty); err != nil || got == "" {
			t.Fatalf("loadRetIntRegTyped(%d, %s) = (%q, %v)", tc.ord, tc.ty, got, err)
		}
	}
	if got, err := c.loadRetIntRegTyped(99, asm.I64); err != nil || got != "0" {
		t.Fatalf("loadRetIntRegTyped(oob) = (%q, %v)", got, err)
	}
	if _, err := c.loadRetIntRegTyped(0, asm.LLVMType("v2i64")); err == nil {
		t.Fatalf("loadRetIntRegTyped(unsupported) unexpectedly succeeded")
	}

	if got, err := c.loadRetFloatRegTyped(0, asm.LLVMType("double")); err != nil || got == "" {
		t.Fatalf("loadRetFloatRegTyped(double) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetFloatRegTyped(0, asm.LLVMType("float")); err != nil || got == "" {
		t.Fatalf("loadRetFloatRegTyped(float) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetFloatRegTyped(99, asm.LLVMType("double")); err != nil || got != "0.000000e+00" {
		t.Fatalf("loadRetFloatRegTyped(oob) = (%q, %v)", got, err)
	}
	if _, err := c.loadRetFloatRegTyped(0, asm.I64); err == nil {
		t.Fatalf("loadRetFloatRegTyped(unsupported) unexpectedly succeeded")
	}

	if isFloat, ord := c.retClassOrdinal(asm.FrameSlot{Index: 3, Type: asm.LLVMType("float")}); !isFloat || ord != 1 {
		t.Fatalf("retClassOrdinal(float) = (%v, %d)", isFloat, ord)
	}
	if got, err := c.loadRetSlotFallback(asm.FrameSlot{Index: 0, Type: asm.I32}); err != nil || got == "" {
		t.Fatalf("loadRetSlotFallback(int) = (%q, %v)", got, err)
	}
	if got, err := c.loadRetSlotFallback(asm.FrameSlot{Index: 2, Type: asm.LLVMType("double")}); err != nil || got == "" {
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
		_, off, ok := asm.ParseSBRef(tc.in)
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
		"bitcast double %arg6 to i64",
		"bitcast float %arg7 to i32",
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
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DI}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.SI}, {Kind: asm.OpReg, Reg: asm.DX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("R8")}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
		},
	}
	sigs := map[string]asm.FuncSig{
		"example.helper": {
			Name:    "example.helper",
			Args:    []asm.LLVMType{asm.I64, asm.I1, asm.I8, asm.I16, asm.I32, asm.Ptr},
			ArgRegs: []asm.Reg{asm.DI, asm.SI, asm.DX, asm.CX, asm.Reg("R8"), asm.Reg("R9")},
			Ret:     asm.Ptr,
		},
		"example.cast": {
			Name: "example.cast",
			Args: []asm.LLVMType{asm.I32, asm.I64},
			Ret:  asm.I64,
		},
		"example.voidret": {
			Name: "example.voidret",
			Args: []asm.LLVMType{asm.I64},
			Ret:  asm.Void,
		},
		"example.badarg": {
			Name: "example.badarg",
			Args: []asm.LLVMType{asm.LLVMType("v2i64")},
			Ret:  asm.I64,
		},
		"example.badret": {
			Name: "example.badret",
			Args: []asm.LLVMType{asm.I64},
			Ret:  asm.LLVMType("double"),
		},
		"example.aggregate": {
			Name: "example.aggregate",
			Ret:  asm.LLVMType("{ ptr, i64 }"),
		},
	}
	sig := asm.FuncSig{
		Name: "example.caller",
		Args: []asm.LLVMType{asm.I64, asm.Ptr},
		Ret:  asm.I64,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, sigs)
	c.blocks = []amd64Block{{name: "entry"}, {name: "fall"}, {name: "target"}}
	c.blockBase = []int{0, 1, 2}
	c.blockByIdx = map[int]int{0: 0, 1: 1, 2: 2}

	if ok, term, err := c.lowerAtomic("LOCK", asm.Instr{Raw: "LOCK"}); !ok || term || err != nil {
		t.Fatalf("lowerAtomic(LOCK) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerAtomic("CMPXCHGL", asm.Instr{
		Raw: "CMPXCHGL CX, 8(BX)",
		Args: []asm.Operand{
			{Kind: asm.OpReg, Reg: asm.CX},
			{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(CMPXCHGL) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XADDQ", asm.Instr{
		Raw: "XADDQ AX, 16(BX)",
		Args: []asm.Operand{
			{Kind: asm.OpReg, Reg: asm.AX},
			{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 16}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XADDQ) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XCHGB", asm.Instr{
		Raw: "XCHGB AX, BX",
		Args: []asm.Operand{
			{Kind: asm.OpReg, Reg: asm.AX},
			{Kind: asm.OpReg, Reg: asm.BX},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XCHGB reg) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("XCHGQ", asm.Instr{
		Raw: "XCHGQ AX, global<>(SB)",
		Args: []asm.Operand{
			{Kind: asm.OpReg, Reg: asm.AX},
			{Kind: asm.OpSym, Sym: "global<>(SB)"},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(XCHGQ sym) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerAtomic("ANDB", asm.Instr{
		Raw: "ANDB $1, 4(BX)",
		Args: []asm.Operand{
			{Kind: asm.OpImm, Imm: 1},
			{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 4}},
		},
	}); !ok || err != nil {
		t.Fatalf("lowerAtomic(ANDB) = (%v, %v)", ok, err)
	}
	if ok, term, err := c.lowerAtomic("ORQ", asm.Instr{
		Raw: "ORQ AX, BX",
		Args: []asm.Operand{
			{Kind: asm.OpReg, Reg: asm.AX},
			{Kind: asm.OpReg, Reg: asm.BX},
		},
	}); ok || term || err != nil {
		t.Fatalf("lowerAtomic(non-mem ORQ) = (%v, %v, %v)", ok, term, err)
	}
	if _, err := c.amd64AtomicTruncFromI64("%x", asm.LLVMType("v2i64")); err == nil {
		t.Fatalf("amd64AtomicTruncFromI64(unsupported) unexpectedly succeeded")
	}
	if _, err := c.amd64AtomicExtendToI64("%x", asm.LLVMType("v2i64")); err == nil {
		t.Fatalf("amd64AtomicExtendToI64(unsupported) unexpectedly succeeded")
	}

	emitBr := func(target string) {
		b.WriteString("  br label %" + asm.LLVMBlockName(target) + "\n")
	}
	emitCondBr := func(cond string, target string, fall string) error {
		b.WriteString("  br i1 " + cond + ", label %" + asm.LLVMBlockName(target) + ", label %" + asm.LLVMBlockName(fall) + "\n")
		return nil
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", asm.Instr{
		Raw:  "CALL helper(SB)",
		Args: []asm.Operand{{Kind: asm.OpSym, Sym: "helper(SB)"}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL sym) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", asm.Instr{
		Raw:  "CALL AX",
		Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL reg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "CALL", asm.Instr{
		Raw:  "CALL 8(BX)",
		Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}},
	}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL mem) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JEQ", asm.Instr{
		Raw:  "JEQ target",
		Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "target"}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JEQ ident) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JMP", asm.Instr{
		Raw:  "JMP 2(PC)",
		Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.PC, Off: 2}}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP pc-rel) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, 0, "JMP", asm.Instr{
		Raw:  "JMP AX",
		Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}},
	}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP reg) = (%v, %v, %v)", ok, term, err)
	}
	if ok, _, err := c.lowerBranch(0, 0, "JEQ", asm.Instr{
		Raw:  "JEQ AX",
		Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}},
	}, emitBr, emitCondBr); !ok || err == nil {
		t.Fatalf("lowerBranch(JEQ reg) = (%v, %v), want error", ok, err)
	}

	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "runtime·entersyscall(SB)"}); err != nil {
		t.Fatalf("callSym(entersyscall) error = %v", err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "helper(SB)"}); err != nil {
		t.Fatalf("callSym(helper) error = %v", err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "aggregate(SB)"}); err != nil {
		t.Fatalf("callSym(aggregate) error = %v", err)
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "badarg(SB)"}); err == nil {
		t.Fatalf("callSym(badarg) unexpectedly succeeded")
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "badret(SB)"}); err == nil {
		t.Fatalf("callSym(badret) unexpectedly succeeded")
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "missing"}); err == nil {
		t.Fatalf("callSym(missing suffix) unexpectedly succeeded")
	}

	if err := c.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "cast(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(cast) error = %v", err)
	}
	if err := c.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "helper(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(helper) error = %v", err)
	}
	cErr, _ := newAMD64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.errcaller", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, sigs)
	if err := cErr.tailCallAndRet(asm.Operand{Kind: asm.OpSym, Sym: "voidret(SB)"}); err == nil {
		t.Fatalf("tailCallAndRet(voidret) unexpectedly succeeded")
	}
	if err := c.tailCallAndRet(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err == nil {
		t.Fatalf("tailCallAndRet(non-sym) unexpectedly succeeded")
	}
	if err := c.tailCallIndirectAddrAndRet("123"); err != nil {
		t.Fatalf("tailCallIndirectAddrAndRet() error = %v", err)
	}

	out := b.String()
	for _, want := range []string{
		"cmpxchg ptr",
		"atomicrmw add ptr",
		"atomicrmw xchg ptr",
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
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DI}, {Kind: asm.OpReg, Reg: asm.SI}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("R8")}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}},
		},
	}
	sig := asm.FuncSig{
		Name: "example.arith",
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I1, Index: 0, Field: -1},
				{Offset: 16, Type: asm.I64, Index: 1, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	mustLower := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerArith(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerArith(%s) = (%v, %v, %v)", op, ok, term, err)
		}
	}

	mustLower("PUSHQ", asm.Instr{Raw: "PUSHQ $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}})
	mustLower("POPQ", asm.Instr{Raw: "POPQ CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("PUSHFQ", asm.Instr{Raw: "PUSHFQ"})
	mustLower("POPFQ", asm.Instr{Raw: "POPFQ"})
	mustLower("LFENCE", asm.Instr{Raw: "LFENCE"})
	mustLower("UNDEF", asm.Instr{Raw: "UNDEF"})
	mustLower("RDTSC", asm.Instr{Raw: "RDTSC"})
	mustLower(asm.OpCPUID, asm.Instr{Raw: "CPUID"})
	mustLower(asm.OpXGETBV, asm.Instr{Raw: "XGETBV"})
	mustLower("RDTSCP", asm.Instr{Raw: "RDTSCP"})
	mustLower("MOVSB", asm.Instr{Raw: "MOVSB"})
	mustLower("MOVSQ", asm.Instr{Raw: "MOVSQ"})
	mustLower("STOSQ", asm.Instr{Raw: "STOSQ"})
	mustLower("NEGL", asm.Instr{Raw: "NEGL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("NEGL", asm.Instr{Raw: "NEGL 4(BX)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 4}}}})
	mustLower("RCRQ", asm.Instr{Raw: "RCRQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADDQ", asm.Instr{Raw: "ADDQ $2, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SUBQ", asm.Instr{Raw: "SUBQ CX, 8(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}})
	mustLower("XORQ", asm.Instr{Raw: "XORQ $3, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ANDQ", asm.Instr{Raw: "ANDQ $4, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 4}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ORQ", asm.Instr{Raw: "ORQ $5, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 5}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADCQ", asm.Instr{Raw: "ADCQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADCB", asm.Instr{Raw: "ADCB $1, AL", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AL}}})
	mustLower("SBBQ", asm.Instr{Raw: "SBBQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADCXQ", asm.Instr{Raw: "ADCXQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADOXQ", asm.Instr{Raw: "ADOXQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADDL", asm.Instr{Raw: "ADDL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ADDB", asm.Instr{Raw: "ADDB CL, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CL}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("SUBL", asm.Instr{Raw: "SUBL CX, 12(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 12}}}})
	mustLower("XORL", asm.Instr{Raw: "XORL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ANDL", asm.Instr{Raw: "ANDL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ORL", asm.Instr{Raw: "ORL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("XORB", asm.Instr{Raw: "XORB $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ANDB", asm.Instr{Raw: "ANDB $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ORB", asm.Instr{Raw: "ORB $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("INCQ", asm.Instr{Raw: "INCQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("DECQ", asm.Instr{Raw: "DECQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("DECQ", asm.Instr{Raw: "DECQ 96(AX)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 96}}}})
	mustLower("INCL", asm.Instr{Raw: "INCL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("DECL", asm.Instr{Raw: "DECL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("DECL", asm.Instr{Raw: "DECL 12(BX)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 12}}}})
	mustLower("LEAQ", asm.Instr{Raw: "LEAQ 8(BX)(CX*2), DI", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Index: asm.CX, Scale: 2, Off: 8}}, {Kind: asm.OpReg, Reg: asm.DI}}})
	mustLower("LEAL", asm.Instr{Raw: "LEAL 4(BX), SI", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 4}}, {Kind: asm.OpReg, Reg: asm.SI}}})
	mustLower("LEAQ", asm.Instr{Raw: "LEAQ ret+16(FP), R8", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 16}, {Kind: asm.OpReg, Reg: asm.Reg("R8")}}})
	mustLower("LEAQ", asm.Instr{Raw: "LEAQ $ret+16(FP), R9", Args: []asm.Operand{{Kind: asm.OpFPAddr, FPOffset: 16}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}})
	mustLower("LEAQ", asm.Instr{Raw: "LEAQ global<>(SB), AX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "global<>(SB)"}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("POPCNTL", asm.Instr{Raw: "POPCNTL AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}})
	mustLower("POPCNTQ", asm.Instr{Raw: "POPCNTQ AX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("TZCNTQ", asm.Instr{Raw: "TZCNTQ BX, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("BSFQ", asm.Instr{Raw: "BSFQ AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}})
	mustLower("BSRQ", asm.Instr{Raw: "BSRQ AX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("BSWAPQ", asm.Instr{Raw: "BSWAPQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("BSFL", asm.Instr{Raw: "BSFL AX, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("BSRL", asm.Instr{Raw: "BSRL AX, DI", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.DI}}})
	mustLower("SETEQ", asm.Instr{Raw: "SETEQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SETGT", asm.Instr{Raw: "SETGT ret+8(FP)", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 8}}})
	mustLower("SETGE", asm.Instr{Raw: "SETGE AH", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AH}}})
	mustLower("SETHI", asm.Instr{Raw: "SETHI BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}}})
	mustLower("SETCS", asm.Instr{Raw: "SETCS AL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AL}}})
	mustLower("SETCS", asm.Instr{Raw: "SETCS AH", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AH}}})
	mustLower("CMOVQEQ", asm.Instr{Raw: "CMOVQEQ CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("CMOVQNE", asm.Instr{Raw: "CMOVQNE CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("CMOVQCS", asm.Instr{Raw: "CMOVQCS CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("CMOVQCC", asm.Instr{Raw: "CMOVQCC CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("CMOVQGT", asm.Instr{Raw: "CMOVQGT CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ANDNL", asm.Instr{Raw: "ANDNL AX, BX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("ANDNQ", asm.Instr{Raw: "ANDNQ AX, BX, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("BEXTRQ", asm.Instr{Raw: "BEXTRQ CX, AX, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("BZHIQ", asm.Instr{Raw: "BZHIQ DI, AX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DI}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("SHRQ", asm.Instr{Raw: "SHRQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SHLQ", asm.Instr{Raw: "SHLQ CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SHLXQ", asm.Instr{Raw: "SHLXQ DI, CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DI}, {Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SARQ", asm.Instr{Raw: "SARQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SARL", asm.Instr{Raw: "SARL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SHLL", asm.Instr{Raw: "SHLL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SHLB", asm.Instr{Raw: "SHLB $2, R10", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("R10")}}})
	mustLower("SHRL", asm.Instr{Raw: "SHRL CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SHRXQ", asm.Instr{Raw: "SHRXQ DI, AX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DI}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("SALQ", asm.Instr{Raw: "SALQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("SALL", asm.Instr{Raw: "SALL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ROLL", asm.Instr{Raw: "ROLL $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("ROLQ", asm.Instr{Raw: "ROLQ CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("RORQ", asm.Instr{Raw: "RORQ $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("RORL", asm.Instr{Raw: "RORL CX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("RORXL", asm.Instr{Raw: "RORXL $1, AX, BX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}})
	mustLower("RORXQ", asm.Instr{Raw: "RORXQ $1, AX, CX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("NOTL", asm.Instr{Raw: "NOTL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("NOTQ", asm.Instr{Raw: "NOTQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("NOTQ", asm.Instr{Raw: "NOTQ 20(BX)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 20}}}})
	mustLower("BSWAPL", asm.Instr{Raw: "BSWAPL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("MULQ", asm.Instr{Raw: "MULQ CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("MULXQ", asm.Instr{Raw: "MULXQ BX, CX, DI", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DI}}})
	mustLower("MULL", asm.Instr{Raw: "MULL CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("DIVL", asm.Instr{Raw: "DIVL CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("IMULQ", asm.Instr{Raw: "IMULQ CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}}})
	mustLower("IMULQ", asm.Instr{Raw: "IMULQ CX, DX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DX}}})
	mustLower("IMUL3Q", asm.Instr{Raw: "IMUL3Q $3, CX, DI", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DI}}})
	mustLower("NEGQ", asm.Instr{Raw: "NEGQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}})

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
	c, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.scalar_validation", Ret: asm.Void}, map[string]asm.FuncSig{
		"example.toowide": {
			Name: "example.toowide",
			Args: []asm.LLVMType{"{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }"},
			Ret:  asm.Void,
		},
		"example.explicit": {
			Name:    "example.explicit",
			Args:    []asm.LLVMType{asm.I64, asm.I64},
			ArgRegs: []asm.Reg{asm.AX},
			Ret:     asm.Void,
		},
	})

	for _, tc := range []struct {
		op  asm.Op
		ins asm.Instr
	}{
		{"BSFQ", asm.Instr{Raw: "BSFQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}},
		{"BSWAPQ", asm.Instr{Raw: "BSWAPQ AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}}},
		{"BSRQ", asm.Instr{Raw: "BSRQ AX, BX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.CX}}}},
		{"POPCNTL", asm.Instr{Raw: "POPCNTL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}},
	} {
		if _, _, err := c.lowerArith(tc.op, tc.ins); err == nil {
			t.Fatalf("%s %q unexpectedly succeeded", tc.op, tc.ins.Raw)
		}
	}
	for _, op := range []asm.Op{"POPCNTL", "POPCNTQ"} {
		for _, ins := range []asm.Instr{
			{Raw: string(op) + " $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}},
			{Raw: string(op) + " bad, AX", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "bad"}, {Kind: asm.OpReg, Reg: asm.AX}}},
			{Raw: string(op) + " X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}},
			{Raw: string(op) + " AX, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}},
		} {
			if ok, term, err := c.lowerArith(op, ins); ok || term || err != nil {
				t.Fatalf("lowerArith(%s) invalid form = (%v, %v, %v), want unsupported", op, ok, term, err)
			}
		}
	}

	cursor := 0
	if _, err := c.structArgFromSequentialRegs(asm.LLVMType("v2i64"), []asm.Reg{asm.AX}, &cursor); err == nil {
		t.Fatal("non-aggregate scalar argument unexpectedly succeeded")
	}
	cursor = 0
	if _, err := c.structArgFromSequentialRegs(asm.LLVMType("{ i64 }"), nil, &cursor); err == nil {
		t.Fatal("aggregate exceeding the register list unexpectedly succeeded")
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "toowide(SB)"}); err == nil {
		t.Fatal("aggregate exceeding the Go ABI register list unexpectedly succeeded")
	}
	if err := c.callSym(asm.Operand{Kind: asm.OpSym, Sym: "explicit(SB)"}); err == nil {
		t.Fatal("incomplete explicit argument-register list unexpectedly succeeded")
	}
}

func TestAMD64SetCSUsesCarryFlag(t *testing.T) {
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.setcs", Ret: asm.Void}, nil)
	if err := c.storeReg(asm.AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 true, ptr " + c.flagsCFSlot + "\n")

	for _, ins := range []asm.Instr{
		{Raw: "SETCS AL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AL}}},
		{Raw: "SETCS AH", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AH}}},
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
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.setge", Ret: asm.Void}, nil)
	if err := c.storeReg(asm.AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 false, ptr " + c.flagsSltSlot + "\n")

	ins := asm.Instr{Raw: "SETGE AH", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AH}}}
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
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.adcb", Ret: asm.Void}, nil)
	if err := c.storeReg(asm.AX, "4660"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	b.WriteString("  store i1 true, ptr " + c.flagsCFSlot + "\n")

	for _, ins := range []asm.Instr{
		{Raw: "ADCB $1, AL", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AL}}},
		{Raw: "ADCB $1, AH", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AH}}},
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
		"add i8",
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
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DI}, {Kind: asm.OpReg, Reg: asm.SI}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("R8")}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X2")}, {Kind: asm.OpReg, Reg: asm.Reg("X3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y2")}, {Kind: asm.OpReg, Reg: asm.Reg("Y3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z2")}, {Kind: asm.OpReg, Reg: asm.Reg("Z3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("K2")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K3")}, {Kind: asm.OpReg, Reg: asm.Reg("X4")}}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.vec", Ret: asm.Void}, nil)
	mustLower := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerVec(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerVec(%s) = (%v, %v, %v)", op, ok, term, err)
		}
	}

	mustLower("MOVL", asm.Instr{Raw: "MOVL $1, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	mustLower("MOVD", asm.Instr{Raw: "MOVD AX, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("MOVQ", asm.Instr{Raw: "MOVQ BX, X2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.Reg("X2")}}})
	mustLower("MOVQ", asm.Instr{Raw: "MOVQ X2, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X2")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("KXORQ", asm.Instr{Raw: "KXORQ K1, K2, K3", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("K2")}, {Kind: asm.OpReg, Reg: asm.Reg("K3")}}})
	mustLower("KMOVB", asm.Instr{Raw: "KMOVB AX, K1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}}})
	mustLower("KMOVW", asm.Instr{Raw: "KMOVW K1, 8(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}})
	mustLower("KMOVQ", asm.Instr{Raw: "KMOVQ K1, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, K1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VGF2P8AFFINEQB", asm.Instr{Raw: "VGF2P8AFFINEQB $1, Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, K1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPOPCNTB", asm.Instr{Raw: "VPOPCNTB Z0, Z1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}})
	mustLower("VPCMPUQ", asm.Instr{Raw: "VPCMPUQ $1, Z0, Z1, K1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}}})
	mustLower("VPCOMPRESSQ", asm.Instr{Raw: "VPCOMPRESSQ Z0, K1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPXORQ", asm.Instr{Raw: "VPXORQ Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPANDQ", asm.Instr{Raw: "VPANDQ Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPORQ", asm.Instr{Raw: "VPORQ Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPXOR", asm.Instr{Raw: "VPXOR Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPOR", asm.Instr{Raw: "VPOR Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPADDD", asm.Instr{Raw: "VPADDD Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPADDQ", asm.Instr{Raw: "VPADDQ Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPXOR", asm.Instr{Raw: "VPXOR X0, X1, X2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X2")}}})
	mustLower("VPSHUFB", asm.Instr{Raw: "VPSHUFB Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPSHUFB", asm.Instr{Raw: "VPSHUFB X0, X1, X2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X2")}}})
	mustLower("VPSHUFD", asm.Instr{Raw: "VPSHUFD $0x1b, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x1b}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPSLLD", asm.Instr{Raw: "VPSLLD $2, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPSRLD", asm.Instr{Raw: "VPSRLD $2, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPSRLQ", asm.Instr{Raw: "VPSRLQ $2, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPSLLQ", asm.Instr{Raw: "VPSLLQ $2, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPALIGNR", asm.Instr{Raw: "VPALIGNR $3, Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPERM2I128", asm.Instr{Raw: "VPERM2I128 $0x21, Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x21}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VINSERTI128", asm.Instr{Raw: "VINSERTI128 $1, X0, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VMOVNTDQ", asm.Instr{Raw: "VMOVNTDQ Y0, 32(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 32}}}})
	mustLower("AESENC", asm.Instr{Raw: "AESENC X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("AESENCLAST", asm.Instr{Raw: "AESENCLAST X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("AESDEC", asm.Instr{Raw: "AESDEC X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("AESDECLAST", asm.Instr{Raw: "AESDECLAST X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("AESIMC", asm.Instr{Raw: "AESIMC X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("AESKEYGENASSIST", asm.Instr{Raw: "AESKEYGENASSIST $1, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("VPTEST", asm.Instr{Raw: "VPTEST Y0, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("PCMPESTRI", asm.Instr{Raw: "PCMPESTRI $0x0c, 48(BX), X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x0c}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 48}}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	mustLower("VPAND", asm.Instr{Raw: "VPAND Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPBLENDD", asm.Instr{Raw: "VPBLENDD $0xaa, Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0xaa}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPBROADCASTB", asm.Instr{Raw: "VPBROADCASTB X0, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}})
	mustLower("VPSRLDQ", asm.Instr{Raw: "VPSRLDQ $3, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VPSLLDQ", asm.Instr{Raw: "VPSLLDQ $3, Y0, Y1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("PUNPCKLBW", asm.Instr{Raw: "PUNPCKLBW X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSHUFL", asm.Instr{Raw: "PSHUFL $0x1b, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x1b}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSHUFHW", asm.Instr{Raw: "PSHUFHW $0x1b, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x1b}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHUFPS", asm.Instr{Raw: "SHUFPS $0x1b, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x1b}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PBLENDW", asm.Instr{Raw: "PBLENDW $0xaa, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0xaa}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA256MSG1", asm.Instr{Raw: "SHA256MSG1 X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA256MSG2", asm.Instr{Raw: "SHA256MSG2 X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA1NEXTE", asm.Instr{Raw: "SHA1NEXTE X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA1MSG1", asm.Instr{Raw: "SHA1MSG1 X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA1MSG2", asm.Instr{Raw: "SHA1MSG2 X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA1RNDS4", asm.Instr{Raw: "SHA1RNDS4 $1, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("SHA256RNDS2", asm.Instr{Raw: "SHA256RNDS2 X0, X1, X2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X2")}}})
	mustLower("VMOVDQU64", asm.Instr{Raw: "VMOVDQU64 Z0, 64(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 64}}}})
	mustLower("VMOVDQU64", asm.Instr{Raw: "VMOVDQU64 64(BX), Z1", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 64}}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}})
	mustLower("VMOVDQU64", asm.Instr{Raw: "VMOVDQU64 Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VMOVDQU", asm.Instr{Raw: "VMOVDQU Y0, 80(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 80}}}})
	mustLower("VMOVDQU", asm.Instr{Raw: "VMOVDQU 80(BX), Y1", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 80}}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	mustLower("VMOVDQU", asm.Instr{Raw: "VMOVDQU X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("VPCMPEQB", asm.Instr{Raw: "VPCMPEQB Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	mustLower("VPMOVMSKB", asm.Instr{Raw: "VPMOVMSKB Y0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("MOVOU", asm.Instr{Raw: "MOVOU 96(BX), X0", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 96}}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	mustLower("MOVOU", asm.Instr{Raw: "MOVOU X0, 112(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 112}}}})
	mustLower("PXOR", asm.Instr{Raw: "PXOR X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PAND", asm.Instr{Raw: "PAND X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PANDN", asm.Instr{Raw: "PANDN X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PADDL", asm.Instr{Raw: "PADDL X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PADDQ", asm.Instr{Raw: "PADDQ X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSUBL", asm.Instr{Raw: "PSUBL X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSLLL", asm.Instr{Raw: "PSLLL $1, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSRLL", asm.Instr{Raw: "PSRLL $1, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSRAL", asm.Instr{Raw: "PSRAL $1, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PCMPEQL", asm.Instr{Raw: "PCMPEQL X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("VPCLMULQDQ", asm.Instr{Raw: "VPCLMULQDQ $0x11, Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x11}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VPTERNLOGD", asm.Instr{Raw: "VPTERNLOGD $0x96, Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x96}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}})
	mustLower("VEXTRACTF32X4", asm.Instr{Raw: "VEXTRACTF32X4 $1, Z0, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	mustLower("PCLMULQDQ", asm.Instr{Raw: "PCLMULQDQ $0x11, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x11}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PCMPEQB", asm.Instr{Raw: "PCMPEQB X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PMOVMSKB", asm.Instr{Raw: "PMOVMSKB X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("PSHUFB", asm.Instr{Raw: "PSHUFB X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PINSRQ", asm.Instr{Raw: "PINSRQ $1, AX, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PINSRD", asm.Instr{Raw: "PINSRD $1, AX, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PINSRW", asm.Instr{Raw: "PINSRW $1, AX, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PINSRB", asm.Instr{Raw: "PINSRB $1, AX, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PEXTRB", asm.Instr{Raw: "PEXTRB $1, X1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("PEXTRB", asm.Instr{Raw: "PEXTRB $1, X1, 128(BX)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 128}}}})
	mustLower("PALIGNR", asm.Instr{Raw: "PALIGNR $3, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSRLDQ", asm.Instr{Raw: "PSRLDQ $3, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSLLDQ", asm.Instr{Raw: "PSLLDQ $3, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PSRLQ", asm.Instr{Raw: "PSRLQ $1, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	mustLower("PEXTRD", asm.Instr{Raw: "PEXTRD $1, X1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.AX}}})
	mustLower("PEXTRD", asm.Instr{Raw: "PEXTRD $1, X1, 136(BX)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 136}}}})

	if _, err := c.loadXVecOperand(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err == nil {
		t.Fatalf("loadXVecOperand(non-x) unexpectedly succeeded")
	}
	if _, err := c.loadYVecOperand(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err == nil {
		t.Fatalf("loadYVecOperand(non-y) unexpectedly succeeded")
	}
	if _, err := c.loadZVecOperand(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err == nil {
		t.Fatalf("loadZVecOperand(non-z) unexpectedly succeeded")
	}
	if got := llvmShiftRightBytesMask(3); !strings.Contains(got, "i32 3") || !strings.Contains(got, "i32 16") {
		t.Fatalf("llvmShiftRightBytesMask(3) = %q", got)
	}
	if got := llvmShiftLeftBytesMask(3); !strings.Contains(got, "i32 16") {
		t.Fatalf("llvmShiftLeftBytesMask(3) = %q", got)
	}
	if got := llvmAlignRightBytesMask(20); !strings.Contains(got, "i32 20") {
		t.Fatalf("llvmAlignRightBytesMask(20) = %q", got)
	}
	if got := llvmAllOnesI8Vec(4); got != "<i8 -1, i8 -1, i8 -1, i8 -1>" {
		t.Fatalf("llvmAllOnesI8Vec(4) = %q", got)
	}
	if !isAMD64ZReg(asm.Reg("Z0")) || isAMD64ZReg(asm.AX) {
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

func TestAMD64SegmentMemoryRejectsInvalidUses(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "segmentErrors", Ret: asm.Void}, nil)
	if _, err := c.addrFromMem(asm.MemRef{Segment: asm.GS}); err == nil {
		t.Fatal("addrFromMem accepted a segment-relative address")
	}
	if _, _, err := c.ptrFromMem(asm.MemRef{Segment: asm.Reg("CS")}); err == nil {
		t.Fatal("ptrFromMem accepted an unsupported segment")
	}
	if ok, _, err := c.lowerMov(asm.OpMOVQ, asm.Instr{Args: []asm.Operand{
		{Kind: asm.OpMem, Mem: asm.MemRef{Segment: asm.Reg("CS")}},
		{Kind: asm.OpReg, Reg: asm.AX},
	}}); !ok || err == nil {
		t.Fatalf("lowerMov(invalid segment) = (%v, %v), want handled error", ok, err)
	}
	var invalidIR strings.Builder
	invalidCtx := newX86Ctx(&invalidIR, asm.Func{}, asm.FuncSig{Name: "example.invalid", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-pc-windows-gnu", false)
	if _, err := invalidCtx.addrFromPlainMem(asm.MemRef{Sym: "(SB)"}); err == nil {
		t.Fatal("symbol-indexed address with an empty symbol unexpectedly succeeded")
	}
}

func TestAMD64TranslateReturnCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: asm.OpTEXT, Raw: "TEXT ·edge(SB),NOSPLIT,$0-0"},
			{Op: "GET_TLS(CX)", Raw: "GET_TLS(CX)"},
			{Op: "NOP", Raw: "NOP"},
		},
	}
	var translated strings.Builder
	if err := TranslateFunc(&translated, fn, asm.FuncSig{Name: "example.edge", Ret: asm.I32}, testResolveSym("example"), nil, "amd64", "", asm.X87Auto, true); err != nil {
		t.Fatalf("TranslateFunc() error = %v", err)
	}
	if !strings.Contains(translated.String(), "ret i32 0") || !strings.Contains(translated.String(), "; s: NOP") {
		t.Fatalf("translateFuncAMD64() output = \n%s", translated.String())
	}

	for _, tc := range []struct {
		name string
		sig  asm.FuncSig
		want string
	}{
		{"void", asm.FuncSig{Name: "example.retvoid", Ret: asm.Void}, "ret void"},
		{"i1", asm.FuncSig{Name: "example.reti1", Ret: asm.I1}, "ret i1"},
		{"i8", asm.FuncSig{Name: "example.reti8", Ret: asm.I8}, "ret i8"},
		{"i16", asm.FuncSig{Name: "example.reti16", Ret: asm.I16}, "ret i16"},
		{"i32", asm.FuncSig{Name: "example.reti32", Ret: asm.I32}, "ret i32"},
		{"i64", asm.FuncSig{Name: "example.reti64", Ret: asm.I64}, "ret i64"},
	} {
		c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, tc.sig, nil)
		if tc.sig.Ret != asm.Void {
			if err := c.storeReg(asm.AX, "19"); err != nil {
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

	cAgg, bAgg := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.retagg",
		Ret:  asm.LLVMType("{ i64, i32 }"),
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I64, Index: 0},
				{Offset: 16, Type: asm.I32, Index: 1},
			},
		},
	}, nil)
	if err := cAgg.storeFPResult(8, asm.I64, "21"); err != nil {
		t.Fatalf("storeFPResult(8) error = %v", err)
	}
	if err := cAgg.lowerRET(); err != nil {
		t.Fatalf("lowerRET(aggregate) error = %v", err)
	}
	if !strings.Contains(bAgg.String(), "insertvalue { i64, i32 }") {
		t.Fatalf("lowerRET(aggregate) output = \n%s", bAgg.String())
	}

	cz, bz := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.zero", Ret: asm.I64}, nil)
	cz.lowerRetZero()
	if !strings.Contains(bz.String(), "ret i64 0") {
		t.Fatalf("lowerRetZero() output = \n%s", bz.String())
	}
}

func TestAMD64FPMovCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X2")}, {Kind: asm.OpReg, Reg: asm.Reg("X3")}}},
		},
	}
	sig := asm.FuncSig{
		Name: "example.fpmov",
		Args: []asm.LLVMType{asm.I64, asm.LLVMType("double"), asm.I64, asm.I64},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.I64, Index: 0, Field: -1},
				{Offset: 8, Type: asm.LLVMType("double"), Index: 1, Field: -1},
				{Offset: 16, Type: asm.I64, Index: 2, Field: -1},
				{Offset: 24, Type: asm.I64, Index: 3, Field: -1},
			},
			Results: []asm.FrameSlot{
				{Offset: 40, Type: asm.LLVMType("double"), Index: 0, Field: -1},
				{Offset: 48, Type: asm.I64, Index: 1, Field: -1},
				{Offset: 56, Type: asm.I16, Index: 2, Field: -1},
				{Offset: 64, Type: asm.I8, Index: 3, Field: -1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	check := func(kind string, ins asm.Instr, ok bool, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s %q error = %v", kind, ins.Raw, err)
		}
		if !ok {
			t.Fatalf("%s %q returned ok=false", kind, ins.Raw)
		}
	}
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "11"},
		{asm.BX, "12"},
		{asm.CX, "13"},
		{asm.DX, "14"},
		{asm.SI, "15"},
		{asm.DI, "16"},
		{asm.Reg("R8"), "17"},
		{asm.Reg("R9"), "18"},
		{asm.Reg("R10"), "19"},
		{asm.Reg("R11"), "20"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	for _, xr := range []asm.Reg{"X0", "X1", "X2", "X3"} {
		if err := c.storeX(xr, "<16 x i8> zeroinitializer"); err != nil {
			t.Fatalf("storeX(%s) error = %v", xr, err)
		}
	}

	for _, ins := range []asm.Instr{
		{Op: "MOVAPD", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.vec(SB)"}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "MOVAPD example.vec(SB), X0"},
		{Op: "ANDPD", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 8}}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "ANDPD 8(AX), X0"},
		{Op: "ANDNPD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "ANDNPD X1, X0"},
		{Op: "ORPD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "ORPD X1, X0"},
		{Op: "XORPS", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "XORPS X1, X0"},
		{Op: "MOVSD", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 7}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "MOVSD $7, X0"},
		{Op: "MOVSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 16}}}, Raw: "MOVSD X0, 16(BX)"},
		{Op: "MOVSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpSym, Sym: "example.f64(SB)"}}, Raw: "MOVSD X0, example.f64(SB)"},
		{Op: "MOVSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpFP, FPOffset: 40}}, Raw: "MOVSD X0, ret+40(FP)"},
		{Op: "ADDSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "ADDSD X0, X1"},
		{Op: "SUBSD", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.CX, Off: 8}}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "SUBSD 8(CX), X1"},
		{Op: "MULSD", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.f64(SB)"}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "MULSD example.f64(SB), X1"},
		{Op: "DIVSD", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 8}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "DIVSD arg+8(FP), X1"},
		{Op: "MAXSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "MAXSD X0, X1"},
		{Op: "MINSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "MINSD X0, X1"},
		{Op: "SQRTSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X2"}}, Raw: "SQRTSD X1, X2"},
		{Op: "COMISD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}}, Raw: "COMISD X0, X1"},
		{Op: "CMPSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpImm, Imm: 7}}, Raw: "CMPSD X0, X1, $7"},
		{Op: "CMPSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpSym, Sym: "5"}}, Raw: "CMPSD X0, X1, 5"},
		{Op: "CVTTSD2SQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: asm.AX}}, Raw: "CVTTSD2SQ X0, AX"},
		{Op: "CVTSQ2SD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: "X2"}}, Raw: "CVTSQ2SD AX, X2"},
		{Op: "CVTSD2SL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: asm.BX}}, Raw: "CVTSD2SL X1, BX"},
		{Op: "CVTSL2SD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: "X0"}}, Raw: "CVTSL2SD AX, X0"},
		{Op: "VADDSD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X2"}}, Raw: "VADDSD X0, X1, X2"},
		{Op: "VFMADD213SD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X2"}}, Raw: "VFMADD213SD X0, X1, X2"},
		{Op: "VFNMADD231SD", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: "X1"}, {Kind: asm.OpReg, Reg: "X2"}}, Raw: "VFNMADD231SD X0, X1, X2"},
	} {
		ok, _, err := c.lowerFP(ins.Op, ins)
		check("lowerFP", ins, ok, err)
	}

	c.setCmpFlags("1", "2")
	for _, ins := range []asm.Instr{
		{Op: "CMOVQLT", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.CX}, {Kind: asm.OpReg, Reg: asm.DX}}, Raw: "CMOVQLT CX, DX"},
		{Op: "MOVLQSX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 21}, {Kind: asm.OpReg, Reg: asm.AX}}, Raw: "MOVLQSX $21, AX"},
		{Op: "MOVLQSX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.CX}}, Raw: "MOVLQSX BX, CX"},
		{Op: "MOVLQSX", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 16}, {Kind: asm.OpReg, Reg: asm.DX}}, Raw: "MOVLQSX arg+16(FP), DX"},
		{Op: "MOVLQSX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.SI, Off: 4}}, {Kind: asm.OpReg, Reg: asm.SI}}, Raw: "MOVLQSX 4(SI), SI"},
		{Op: "MOVLQSX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.i32(SB)"}, {Kind: asm.OpReg, Reg: asm.DI}}, Raw: "MOVLQSX example.i32(SB), DI"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 31}, {Kind: asm.OpReg, Reg: asm.AX}}, Raw: "MOVQ $31, AX"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.BX}}, Raw: "MOVQ 8(BX), BX"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.i64(SB)"}, {Kind: asm.OpReg, Reg: asm.CX}}, Raw: "MOVQ example.i64(SB), CX"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpFP, FPOffset: 48}}, Raw: "MOVQ AX, ret+48(FP)"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.DX, Off: 8}}}, Raw: "MOVQ AX, 8(DX)"},
		{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "example.i64(SB)"}}, Raw: "MOVQ AX, example.i64(SB)"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 41}, {Kind: asm.OpReg, Reg: asm.DX}}, Raw: "MOVL $41, DX"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.SI, Off: 8}}, {Kind: asm.OpReg, Reg: asm.Reg("R8")}}, Raw: "MOVL 8(SI), R8"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.i32(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}, Raw: "MOVL example.i32(SB), R9"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpFP, FPOffset: 48}}, Raw: "MOVL AX, ret+48(FP)"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.DI, Off: 8}}}, Raw: "MOVL AX, 8(DI)"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0xf1}, {Kind: asm.OpImm, Imm: 0xf1}}, Raw: "MOVL $0xf1, 0xf1"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "example.i32(SB)"}}, Raw: "MOVL AX, example.i32(SB)"},
		{Op: "MOVLQZX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 12}}, {Kind: asm.OpReg, Reg: asm.Reg("R10")}}, Raw: "MOVLQZX 12(AX), R10"},
		{Op: "MOVBQZX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 13}}, {Kind: asm.OpReg, Reg: asm.Reg("R11")}}, Raw: "MOVBQZX 13(AX), R11"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 9}, {Kind: asm.OpReg, Reg: asm.BX}}, Raw: "MOVB $9, BX"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 2}}, {Kind: asm.OpReg, Reg: asm.CX}}, Raw: "MOVB 2(BX), CX"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 16}, {Kind: asm.OpReg, Reg: asm.DX}}, Raw: "MOVB arg+16(FP), DX"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.b(SB)"}, {Kind: asm.OpReg, Reg: asm.SI}}, Raw: "MOVB example.b(SB), SI"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpFP, FPOffset: 64}}, Raw: "MOVB AX, ret+64(FP)"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.DI, Off: 3}}}, Raw: "MOVB AX, 3(DI)"},
		{Op: "MOVB", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "example.b(SB)"}}, Raw: "MOVB AX, example.b(SB)"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 10}, {Kind: asm.OpReg, Reg: asm.SI}}, Raw: "MOVW $10, SI"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.SI, Off: 2}}, {Kind: asm.OpReg, Reg: asm.DI}}, Raw: "MOVW 2(SI), DI"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 16}, {Kind: asm.OpReg, Reg: asm.Reg("R8")}}, Raw: "MOVW arg+16(FP), R8"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.w(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("R9")}}, Raw: "MOVW example.w(SB), R9"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpFP, FPOffset: 56}}, Raw: "MOVW AX, ret+56(FP)"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.DI, Off: 4}}}, Raw: "MOVW AX, 4(DI)"},
		{Op: "MOVW", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "example.w(SB)"}}, Raw: "MOVW AX, example.w(SB)"},
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
	if got, err := c.evalF64(asm.Operand{Kind: asm.OpFP, FPOffset: 8}); err != nil || got == "" {
		t.Fatalf("evalF64(double fp) = (%q, %v)", got, err)
	}
	if got, err := c.evalF64(asm.Operand{Kind: asm.OpFP, FPOffset: 16}); err != nil || got == "" {
		t.Fatalf("evalF64(i64 fp) = (%q, %v)", got, err)
	}
	c.fpParams[32] = asm.FrameSlot{Offset: 32, Type: asm.I32, Index: 2, Field: -1}
	if _, err := c.evalF64(asm.Operand{Kind: asm.OpFP, FPOffset: 32}); err == nil {
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
	sig := asm.FuncSig{
		Name: "example.cmpbt",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params:  []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0}},
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "11"},
		{asm.BX, "12"},
		{asm.CX, "13"},
		{asm.DX, "14"},
		{asm.SI, "15"},
		{asm.DI, "16"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	check := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerCmpBt(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerCmpBt(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	check("CMPB", asm.Instr{Raw: "CMPB $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	check("CMPW", asm.Instr{Raw: "CMPW 4(BX), CX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 4}}, {Kind: asm.OpReg, Reg: asm.CX}}})
	check("CMPL", asm.Instr{Raw: "CMPL arg+0(FP), DI", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpReg, Reg: asm.DI}}})
	check("CMPQ", asm.Instr{Raw: "CMPQ example.global(SB), SI", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.SI}}})
	check("TESTB", asm.Instr{Raw: "TESTB AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}})
	check("TESTW", asm.Instr{Raw: "TESTW $7, arg+0(FP)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 7}, {Kind: asm.OpFP, FPOffset: 0}}})
	check("TESTL", asm.Instr{Raw: "TESTL $const, 8(BX)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "$const"}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}})
	check("TESTQ", asm.Instr{Raw: "TESTQ example.global(SB), DI", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.DI}}})
	check("BTQ", asm.Instr{Raw: "BTQ $3, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.AX}}})
	check("BTSQ", asm.Instr{Raw: "BTSQ DX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DX}, {Kind: asm.OpReg, Reg: asm.AX}}})
	check("BTRQ", asm.Instr{Raw: "BTRQ $63, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 63}, {Kind: asm.OpReg, Reg: asm.AX}}})
	check("BTRQ", asm.Instr{Raw: "BTRQ DX, (BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX}}}})

	if ok, term, err := c.lowerCmpBt("BAD", asm.Instr{}); ok || term || err != nil {
		t.Fatalf("lowerCmpBt(BAD) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerCmpBt("CMPQ", asm.Instr{Raw: "CMPQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("short CMPQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("TESTQ", asm.Instr{Raw: "TESTQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("short TESTQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTQ", asm.Instr{Raw: "BTQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("short BTQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTSQ", asm.Instr{Raw: "BTSQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("short BTSQ unexpectedly succeeded")
	}
	if _, _, err := c.lowerCmpBt("BTRQ", asm.Instr{Raw: "BTRQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("short BTRQ unexpectedly succeeded")
	}
	if got, err := c.evalIntSized(asm.Operand{Kind: asm.OpSym, Sym: "$const"}, asm.I32); err != nil || got != "0" {
		t.Fatalf("evalIntSized($const) = (%q, %v)", got, err)
	}
	if _, err := c.evalIntSized(asm.Operand{Kind: asm.OpSym, Sym: "bad"}, asm.I32); err == nil {
		t.Fatalf("evalIntSized(bad sym) unexpectedly succeeded")
	}
	if _, err := c.evalIntSized(asm.Operand{Kind: asm.OpIdent, Ident: "label"}, asm.I32); err == nil {
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
	sig := asm.FuncSig{
		Name: "example.mov",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params:  []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0}},
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0}, {Offset: 16, Type: asm.I16, Index: 1}, {Offset: 24, Type: asm.I8, Index: 2}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "21"},
		{asm.BX, "22"},
		{asm.CX, "23"},
		{asm.DX, "24"},
		{asm.SI, "25"},
		{asm.DI, "26"},
		{asm.Reg("R8"), "27"},
		{asm.Reg("R9"), "28"},
		{asm.Reg("R10"), "29"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	checkMov := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerMov(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerMov(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	checkMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX $7, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 7}, {Kind: asm.OpReg, Reg: asm.AX}}})
	checkMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX BX, CX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpReg, Reg: asm.CX}}})
	checkMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX arg+0(FP), DX", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpReg, Reg: asm.DX}}})
	checkMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX 8(BX), SI", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.SI}}})
	checkMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX example.global(SB), DI", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.DI}}})
	checkMov("MOVWQSX", asm.Instr{Raw: "MOVWQSX 8(BX), SI", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.SI}}})
	b.WriteString("  store i1 true, ptr " + c.flagsSltSlot + "\n")
	checkMov("CMOVQLT", asm.Instr{Raw: "CMOVQLT AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}})
	checkMov("MOVB", asm.Instr{Raw: "MOVB $1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}}})
	checkMov("MOVBLZX", asm.Instr{Raw: "MOVBLZX 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}})
	checkMov("MOVB", asm.Instr{Raw: "MOVB BX, ret+24(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpFP, FPOffset: 24}}})
	checkMov("MOVW", asm.Instr{Raw: "MOVW arg+0(FP), 8(BX)", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}})
	checkMov("MOVWLZX", asm.Instr{Raw: "MOVWLZX 8(BX), CX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.CX}}})
	checkMov("MOVWQZX", asm.Instr{Raw: "MOVWQZX 8(BX), DX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.DX}}})
	checkMov("MOVW", asm.Instr{Raw: "MOVW example.global(SB), example.dest(SB)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVQ", asm.Instr{Raw: "MOVQ example.global(SB), CX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.CX}}})
	checkMov("MOVQ", asm.Instr{Raw: "MOVQ DX, ret+8(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.DX}, {Kind: asm.OpFP, FPOffset: 8}}})
	checkMov("MOVQ", asm.Instr{Raw: "MOVQ $9, 16(BX)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 9}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 16}}}})
	checkMov("MOVQ", asm.Instr{Raw: "MOVQ SI, example.dest(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.SI}, {Kind: asm.OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVL", asm.Instr{Raw: "MOVL $10, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 10}, {Kind: asm.OpReg, Reg: asm.AX}}})
	checkMov("MOVL", asm.Instr{Raw: "MOVL BX, ret+8(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.BX}, {Kind: asm.OpFP, FPOffset: 8}}})
	checkMov("MOVL", asm.Instr{Raw: "MOVL arg+0(FP), 20(BX)", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 20}}}})
	checkMov("MOVL", asm.Instr{Raw: "MOVL 24(BX), example.dest(SB)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 24}}, {Kind: asm.OpSym, Sym: "example.dest(SB)"}}})
	checkMov("MOVL", asm.Instr{Raw: "MOVL $0xf1, 0xf1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0xf1}, {Kind: asm.OpImm, Imm: 0xf1}}})

	if ok, term, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}}); ok || term || err != nil {
		t.Fatalf("lowerMov(vector) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX AX, 8(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}}); err == nil {
		t.Fatalf("MOVLQSX non-reg dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVB", asm.Instr{Raw: "MOVB label, AX", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, {Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("MOVB bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVW", asm.Instr{Raw: "MOVW AX, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVW bad sym dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ AX, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpLabel, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVQ bad dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVL", asm.Instr{Raw: "MOVL label, AX", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, {Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("MOVL bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("MOVQ short arg list unexpectedly succeeded")
	}
	if ok, term, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ Y0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
		t.Fatalf("MOVQ yreg src = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ AX, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}}); ok || term || err != nil {
		t.Fatalf("MOVQ yreg dst = (%v, %v, %v)", ok, term, err)
	}

	cBadReg, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	if ok, term, err := cBadReg.lowerMov("MOVB", asm.Instr{Raw: "MOVB BAD, ret+24(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("BAD")}, {Kind: asm.OpFP, FPOffset: 24}}}); !ok || term || err != nil {
		t.Fatalf("MOVB missing src reg = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("CMOVQLT", asm.Instr{Raw: "CMOVQLT BAD, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("BAD")}, {Kind: asm.OpReg, Reg: asm.BX}}}); !ok || term || err != nil {
		t.Fatalf("CMOVQLT missing regs = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ BAD, 8(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("BAD")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ missing mem base = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadReg.lowerMov("MOVL", asm.Instr{Raw: "MOVL BAD, ret+8(FP)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("BAD")}, {Kind: asm.OpFP, FPOffset: 8}}}); !ok || term || err != nil {
		t.Fatalf("MOVL missing reg = (%v, %v, %v)", ok, term, err)
	}

	cBadMem, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	if ok, term, err := cBadMem.lowerMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX 8(BAD), SI", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg("BAD"), Off: 8}}, {Kind: asm.OpReg, Reg: asm.SI}}}); !ok || term || err != nil {
		t.Fatalf("MOVLQSX bad mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVW", asm.Instr{Raw: "MOVW arg+0(FP), 8(BAD)", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg("BAD"), Off: 8}}}}); !ok || term || err != nil {
		t.Fatalf("MOVW bad dst mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ 8(BAD), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg("BAD"), Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad src mem = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := cBadMem.lowerMov("MOVL", asm.Instr{Raw: "MOVL 24(BAD), example.dest(SB)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg("BAD"), Off: 24}}, {Kind: asm.OpSym, Sym: "example.dest(SB)"}}}); !ok || term || err != nil {
		t.Fatalf("MOVL bad src mem = (%v, %v, %v)", ok, term, err)
	}

	if ok, term, err := c.lowerMov("MOVLQSX", asm.Instr{Raw: "MOVLQSX broken, AX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "broken"}, {Kind: asm.OpReg, Reg: asm.AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVLQSX bad sym = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVB", asm.Instr{Raw: "MOVB broken, AX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "broken"}, {Kind: asm.OpReg, Reg: asm.AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVB bad sym = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ broken, AX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "broken"}, {Kind: asm.OpReg, Reg: asm.AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad sym src = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVQ", asm.Instr{Raw: "MOVQ AX, broken", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpSym, Sym: "broken"}}}); !ok || term || err != nil {
		t.Fatalf("MOVQ bad sym dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerMov("MOVL", asm.Instr{Raw: "MOVL broken, AX", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "broken"}, {Kind: asm.OpReg, Reg: asm.AX}}}); !ok || term || err != nil {
		t.Fatalf("MOVL bad sym src = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerMov("MOVL", asm.Instr{Raw: "MOVL AX, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpLabel, Sym: "label"}}}); err == nil {
		t.Fatalf("MOVL bad dst unexpectedly succeeded")
	}

	sysc, sysb := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.sys", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "1"},
		{asm.DI, "2"},
		{asm.SI, "3"},
		{asm.DX, "4"},
		{asm.Reg("R10"), "5"},
		{asm.Reg("R8"), "6"},
		{asm.Reg("R9"), "7"},
		{asm.BX, "256"},
	} {
		if err := sysc.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("sys storeReg(%s) error = %v", tc.r, err)
		}
	}
	if ok, term, err := sysc.lowerSyscall("INT", asm.Instr{Raw: "INT $3"}); !ok || !term || err != nil {
		t.Fatalf("lowerSyscall(INT) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := sysc.lowerSyscall("SYSCALL", asm.Instr{Raw: "SYSCALL"}); !ok || term || err != nil {
		t.Fatalf("lowerSyscall(SYSCALL) = (%v, %v, %v)", ok, term, err)
	}
	for _, tc := range []asm.Instr{
		{Op: "CRC32B", Raw: "CRC32B 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}},
		{Op: "CRC32W", Raw: "CRC32W 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}},
		{Op: "CRC32L", Raw: "CRC32L 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}},
		{Op: "CRC32Q", Raw: "CRC32Q 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}},
	} {
		if ok, term, err := sysc.lowerCrc32(tc.Op, tc); !ok || term || err != nil {
			t.Fatalf("lowerCrc32(%s) = (%v, %v, %v)", tc.Op, ok, term, err)
		}
	}
	if _, _, err := sysc.lowerSyscall("SYSCALL", asm.Instr{Raw: "SYSCALL AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("SYSCALL with args unexpectedly succeeded")
	}
	if ok, term, err := sysc.lowerSyscall("BAD", asm.Instr{}); ok || term || err != nil {
		t.Fatalf("lowerSyscall(BAD) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := sysc.lowerCrc32("CRC32B", asm.Instr{Raw: "CRC32B AX, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}}); !ok || term || err != nil {
		t.Fatalf("CRC32B reg, reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := sysc.lowerCrc32("CRC32B", asm.Instr{Raw: "CRC32B $1, BX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.BX}}}); err == nil {
		t.Fatalf("bad CRC32B unexpectedly succeeded")
	}
	if ok, term, err := sysc.lowerCrc32("BAD", asm.Instr{}); ok || term || err != nil {
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
	fn := asm.Func{Instrs: []asm.Instr{{Op: "NOP"}, {Op: "NOP"}, {Op: "NOP"}, {Op: "NOP"}}}
	sigs := map[string]asm.FuncSig{
		"example.tail": {Name: "example.tail", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.branch", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, sigs)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "31"},
		{asm.BX, "32"},
		{asm.CX, "33"},
		{asm.DX, "34"},
		{asm.DI, "35"},
		{asm.SI, "36"},
		{asm.Reg("R8"), "37"},
		{asm.Reg("R9"), "38"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	c.blocks = []amd64Block{{name: "entry"}, {name: "fall"}, {name: "V1"}, {name: "tail"}}
	c.blockBase = []int{0, 1, 2, 3}
	c.blockByIdx = map[int]int{0: 0, 1: 1, 2: 2, 3: 3}
	c.setCmpFlags("1", "2")

	emitBr := func(target string) { b.WriteString("  br label %" + asm.LLVMBlockName(target) + "\n") }
	emitCondBr := func(cond string, target string, fall string) error {
		b.WriteString("  br i1 " + cond + ", label %" + asm.LLVMBlockName(target) + ", label %" + asm.LLVMBlockName(fall) + "\n")
		return nil
	}
	for _, tc := range []struct {
		op  asm.Op
		ins asm.Instr
	}{
		{"JE", asm.Instr{Raw: "JE V1", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "V1"}}}},
		{"JNE", asm.Instr{Raw: "JNE tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JL", asm.Instr{Raw: "JL V1<>(SB)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "V1<>(SB)"}}}},
		{"JGE", asm.Instr{Raw: "JGE 2(PC)", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.PC, Off: 2}}}}},
		{"JS", asm.Instr{Raw: "JS tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JNS", asm.Instr{Raw: "JNS V1", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "V1"}}}},
		{"JLE", asm.Instr{Raw: "JLE tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JG", asm.Instr{Raw: "JG V1", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "V1"}}}},
		{"JB", asm.Instr{Raw: "JB tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JNC", asm.Instr{Raw: "JNC V1", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "V1"}}}},
		{"JAE", asm.Instr{Raw: "JAE tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JBE", asm.Instr{Raw: "JBE V1", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "V1"}}}},
		{"JNA", asm.Instr{Raw: "JNA tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JA", asm.Instr{Raw: "JA tail", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "tail"}}}},
		{"JMP", asm.Instr{Raw: "JMP V1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("V1")}}}},
		{"JMP", asm.Instr{Raw: "JMP tail(SB)", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "tail(SB)"}}}},
	} {
		if ok, term, err := c.lowerBranch(0, 0, tc.op, tc.ins, emitBr, emitCondBr); !ok || !term || err != nil {
			t.Fatalf("lowerBranch(%s %q) = (%v, %v, %v)", tc.op, tc.ins.Raw, ok, term, err)
		}
	}
	if _, _, err := c.lowerBranch(0, 0, "CALL", asm.Instr{Raw: "CALL $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}}, emitBr, emitCondBr); err == nil {
		t.Fatalf("CALL imm unexpectedly succeeded")
	}
	if ok, term, err := c.lowerBranch(0, 0, "JMP", asm.Instr{Raw: "JMP $1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("JMP imm = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerBranch(0, 0, "JMP", asm.Instr{Raw: "JMP", Args: nil}, emitBr, emitCondBr); err == nil {
		t.Fatalf("JMP without target unexpectedly succeeded")
	}
	if _, _, err := c.lowerBranch(0, 0, "JEQ", asm.Instr{Raw: "JEQ", Args: nil}, emitBr, emitCondBr); err == nil {
		t.Fatalf("JEQ without target unexpectedly succeeded")
	}
	oneBlock, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.one", Ret: asm.Void}, nil)
	oneBlock.blocks = []amd64Block{{name: "solo"}}
	oneBlock.blockBase = []int{0}
	oneBlock.blockByIdx = map[int]int{0: 0}
	oneBlock.setCmpFlags("1", "1")
	if _, _, err := oneBlock.lowerBranch(0, 0, "JEQ", asm.Instr{Raw: "JEQ solo", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "solo"}}}, emitBr, emitCondBr); err == nil {
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
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}},
		},
	}
	sig := asm.FuncSig{
		Name: "example.fpextra",
		Args: []asm.LLVMType{asm.I64, asm.LLVMType("double")},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.I64, Index: 0},
				{Offset: 8, Type: asm.LLVMType("double"), Index: 1},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "51"},
		{asm.BX, "52"},
		{asm.Reg("X0"), "<16 x i8> zeroinitializer"},
		{asm.Reg("X1"), "<16 x i8> zeroinitializer"},
		{asm.Reg("Y0"), "<32 x i8> zeroinitializer"},
		{asm.Reg("Y1"), "<32 x i8> zeroinitializer"},
		{asm.Reg("Z0"), "<64 x i8> zeroinitializer"},
		{asm.Reg("Z1"), "<64 x i8> zeroinitializer"},
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

	if got, err := c.loadYVecOperand(asm.Operand{Kind: asm.OpReg, Reg: asm.Reg("Y0")}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(reg) = (%q, %v)", got, err)
	}
	if got, err := c.loadYVecOperand(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 8}}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(mem) = (%q, %v)", got, err)
	}
	if got, err := c.loadYVecOperand(asm.Operand{Kind: asm.OpSym, Sym: "example.vec32(SB)"}); err != nil || got == "" {
		t.Fatalf("loadYVecOperand(sym) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(asm.Operand{Kind: asm.OpReg, Reg: asm.Reg("Z0")}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(reg) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.AX, Off: 16}}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(mem) = (%q, %v)", got, err)
	}
	if got, err := c.loadZVecOperand(asm.Operand{Kind: asm.OpSym, Sym: "example.vec64(SB)"}); err != nil || got == "" {
		t.Fatalf("loadZVecOperand(sym) = (%q, %v)", got, err)
	}

	check := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerFP(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerFP(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}
	for _, pred := range []int64{0, 1, 2, 3, 4, 6} {
		check("CMPSD", asm.Instr{Raw: "CMPSD X0, X1, $pred", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpImm, Imm: pred}}})
	}
	check("VADDSD", asm.Instr{Raw: "VADDSD X0, X1, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("VFMADD213SD", asm.Instr{Raw: "VFMADD213SD X0, X1, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("VFNMADD231SD", asm.Instr{Raw: "VFNMADD231SD X0, X1, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})

	if ok, term, err := c.lowerFP("MOVAPD", asm.Instr{Raw: "MOVAPD X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
		t.Fatalf("MOVAPD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerFP("MOVSD", asm.Instr{Raw: "MOVSD X0, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("MOVSD bad dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerFP("ADDSD", asm.Instr{Raw: "ADDSD X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
		t.Fatalf("ADDSD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerFP("SQRTSD", asm.Instr{Raw: "SQRTSD X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
		t.Fatalf("SQRTSD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerFP("COMISD", asm.Instr{Raw: "COMISD X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}}}); err == nil {
		t.Fatalf("COMISD short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerFP("CMPSD", asm.Instr{Raw: "CMPSD X0, X1, bad", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpSym, Sym: "bad"}}}); err == nil {
		t.Fatalf("CMPSD bad sym predicate unexpectedly succeeded")
	}
	if _, _, err := c.lowerFP("CMPSD", asm.Instr{Raw: "CMPSD X0, X1, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("CMPSD reg predicate unexpectedly succeeded")
	}
	if ok, term, err := c.lowerFP("CVTSQ2SD", asm.Instr{Raw: "CVTSQ2SD AX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
		t.Fatalf("CVTSQ2SD non-X dst = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerFP("CVTSL2SD", asm.Instr{Raw: "CVTSL2SD AX, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.AX}}}); ok || term || err != nil {
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
		"fmul double",
		"fneg double",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestAMD64VectorAliasAndErrorCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X2")}, {Kind: asm.OpReg, Reg: asm.Reg("X3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y2")}, {Kind: asm.OpReg, Reg: asm.Reg("Y3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z2")}, {Kind: asm.OpReg, Reg: asm.Reg("Z3")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("K2")}}},
			{Op: "MOVQ", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("K3")}, {Kind: asm.OpReg, Reg: asm.Reg("K4")}}},
		},
	}
	sig := asm.FuncSig{
		Name: "example.vecalias",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, fn, sig, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "61"},
		{asm.BX, "62"},
		{asm.CX, "63"},
		{asm.DX, "64"},
		{asm.Reg("K1"), "1"},
		{asm.Reg("K2"), "2"},
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

	check := func(op asm.Op, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerVec(op, ins); !ok || term || err != nil {
			t.Fatalf("lowerVec(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	check("VZEROUPPER", asm.Instr{Raw: "VZEROUPPER"})
	check("VZEROALL", asm.Instr{Raw: "VZEROALL"})
	check("VMOVDQA", asm.Instr{Raw: "VMOVDQA Y0, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	check("VMOVDQA64", asm.Instr{Raw: "VMOVDQA64 Z0, Z1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}})
	check("VPERM2F128", asm.Instr{Raw: "VPERM2F128 $1, Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	check("VMOVAPS", asm.Instr{Raw: "VMOVAPS Z0, Z1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}})
	check("VMOVAPD", asm.Instr{Raw: "VMOVAPD Y0, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}})
	check("VPXORQ", asm.Instr{Raw: "VPXORQ Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	check("VPANDQ", asm.Instr{Raw: "VPANDQ Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	check("VPORQ", asm.Instr{Raw: "VPORQ Y0, Y1, Y2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y2")}}})
	check("MOVUPS", asm.Instr{Raw: "MOVUPS 8(BX), X0", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("MOVAPS", asm.Instr{Raw: "MOVAPS X0, 16(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 16}}}})
	check("MOVO", asm.Instr{Raw: "MOVO X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	check("MOVQ", asm.Instr{Raw: "MOVQ arg+0(FP), X0", Args: []asm.Operand{{Kind: asm.OpFP, FPOffset: 0}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("MOVQ", asm.Instr{Raw: "MOVQ 24(BX), X1", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 24}}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}})
	check("MOVQ", asm.Instr{Raw: "MOVQ example.global(SB), X2", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("X2")}}})
	check("MOVQ", asm.Instr{Raw: "MOVQ X0, 32(BX)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 32}}}})
	check("MOVOU", asm.Instr{Raw: "MOVOU example.global(SB), X0", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.global(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("MOVOA", asm.Instr{Raw: "MOVOA X0, example.out(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpSym, Sym: "example.out(SB)"}}})
	check("KMOVB", asm.Instr{Raw: "KMOVB 8(BX), K1", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}}})
	check("KMOVQ", asm.Instr{Raw: "KMOVQ 8(BX), AX", Args: []asm.Operand{{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.AX}}})
	check("VMOVDQU64", asm.Instr{Raw: "VMOVDQU64 example.zin(SB), Z0", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.zin(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}}})
	check("VMOVDQU64", asm.Instr{Raw: "VMOVDQU64 Z0, example.zout(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpSym, Sym: "example.zout(SB)"}}})
	check("VMOVDQU", asm.Instr{Raw: "VMOVDQU example.yin(SB), Y0", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.yin(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}})
	check("VMOVDQU", asm.Instr{Raw: "VMOVDQU Y0, example.yout(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpSym, Sym: "example.yout(SB)"}}})
	check("VMOVDQU", asm.Instr{Raw: "VMOVDQU example.xin(SB), X0", Args: []asm.Operand{{Kind: asm.OpSym, Sym: "example.xin(SB)"}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}})
	check("VMOVDQU", asm.Instr{Raw: "VMOVDQU X0, example.xout(SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpSym, Sym: "example.xout(SB)"}}})
	check("PEXTRB", asm.Instr{Raw: "PEXTRB $1, X1, example.byteout(SB)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}, {Kind: asm.OpSym, Sym: "example.byteout(SB)"}}})

	if _, _, err := c.lowerVec("MOVL", asm.Instr{Raw: "MOVL label, X0", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}); err == nil {
		t.Fatalf("MOVL bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("MOVQ", asm.Instr{Raw: "MOVQ label, X0", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}); err == nil {
		t.Fatalf("MOVQ bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("MOVQ", asm.Instr{Raw: "MOVQ X0, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("MOVQ bad dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("KXORQ", asm.Instr{Raw: "KXORQ AX, K1, K2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("K2")}}}); ok || term || err != nil {
		t.Fatalf("KXORQ non-k src = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("KMOVB", asm.Instr{Raw: "KMOVB AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("KMOVB short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("KMOVB", asm.Instr{Raw: "KMOVB label, AX", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, {Kind: asm.OpReg, Reg: asm.AX}}}); err == nil {
		t.Fatalf("KMOVB bad src unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("KMOVB", asm.Instr{Raw: "KMOVB AX, label", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpIdent, Ident: "label"}}}); err == nil {
		t.Fatalf("KMOVB bad dst unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMB", asm.Instr{Raw: "VPERMB Z0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}}}); err == nil {
		t.Fatalf("VPERMB short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, 7", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpImm, Imm: 7}}}); err == nil {
		t.Fatalf("VPERMB non-reg dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}); ok || term || err != nil {
		t.Fatalf("VPERMB wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, 7, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpImm, Imm: 7}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}); err == nil {
		t.Fatalf("VPERMB non-reg mask unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMB", asm.Instr{Raw: "VPERMB Z0, Z1, AX, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}); ok || term || err != nil {
		t.Fatalf("VPERMB wrong mask reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VGF2P8AFFINEQB", asm.Instr{Raw: "VGF2P8AFFINEQB Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}); err == nil {
		t.Fatalf("VGF2P8AFFINEQB short form unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VGF2P8AFFINEQB", asm.Instr{Raw: "VGF2P8AFFINEQB $1, Z0, Z1, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}); ok || term || err != nil {
		t.Fatalf("VGF2P8AFFINEQB wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}}}); err == nil {
		t.Fatalf("VPERMI2B short form unexpectedly succeeded")
	}
	if _, _, err := c.lowerVec("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, 7", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpImm, Imm: 7}}}); err == nil {
		t.Fatalf("VPERMI2B non-reg dst unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}); ok || term || err != nil {
		t.Fatalf("VPERMI2B wrong dst reg = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerVec("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, 7, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpImm, Imm: 7}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}); err == nil {
		t.Fatalf("VPERMI2B non-reg mask unexpectedly succeeded")
	}
	if ok, term, err := c.lowerVec("VPERMI2B", asm.Instr{Raw: "VPERMI2B Z0, Z1, AX, Z2", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}); ok || term || err != nil {
		t.Fatalf("VPERMI2B wrong mask reg = (%v, %v, %v)", ok, term, err)
	}
	for _, tc := range []struct {
		op          asm.Op
		ins         asm.Instr
		want        string
		wantHandled bool
	}{
		{"VPOPCNTB", asm.Instr{Raw: "VPOPCNTB Z0, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst", false},
		{"VPCMPUQ", asm.Instr{Raw: "VPCMPUQ $3, Z0, Z1, K1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 3}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}}}, "delegate imm 3", false},
		{"VPCMPUQ", asm.Instr{Raw: "VPCMPUQ $1, Z0, Z1, AX", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "wrong dst reg", false},
		{"VPCOMPRESSQ", asm.Instr{Raw: "VPCOMPRESSQ Z0, AX, Z1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}}}, "wrong mask", false},
		{"VPCOMPRESSQ", asm.Instr{Raw: "VPCOMPRESSQ Z0, K1, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("K1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst", false},
		{"VPXORQ", asm.Instr{Raw: "VPXORQ Z0, Z1, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong z dst", true},
		{"VPSHUFB", asm.Instr{Raw: "VPSHUFB Y0, Y1, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "wrong dst", false},
		{"VPSHUFD", asm.Instr{Raw: "VPSHUFD $1, X0, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong src class", false},
		{"VPSLLD", asm.Instr{Raw: "VPSLLD Y0, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}}, "short form", true},
		{"VPERM2I128", asm.Instr{Raw: "VPERM2I128 $1, Y0, Y1, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong dst", false},
		{"VINSERTI128", asm.Instr{Raw: "VINSERTI128 $1, X0, Y0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}}, "wrong dst", false},
		{"VMOVNTDQ", asm.Instr{Raw: "VMOVNTDQ Y0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "bad dst", true},
		{"AESKEYGENASSIST", asm.Instr{Raw: "AESKEYGENASSIST X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}}, "missing imm", true},
		{"VPTEST", asm.Instr{Raw: "VPTEST X0, Y0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong src class", false},
		{"PCMPESTRI", asm.Instr{Raw: "PCMPESTRI $1, 8(BX), X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "delegate non-0x0c imm", false},
		{"PCMPESTRI", asm.Instr{Raw: "PCMPESTRI $0x0c, AX, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x0c}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "bad mem operand", true},
		{"VPBLENDD", asm.Instr{Raw: "VPBLENDD $1, Y0, Y1, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong dst", false},
		{"VPBROADCASTB", asm.Instr{Raw: "VPBROADCASTB Y0, Y1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y1")}}}, "wrong src", false},
		{"VPSRLDQ", asm.Instr{Raw: "VPSRLDQ $2, X0, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 2}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong src class", false},
		{"PUNPCKLBW", asm.Instr{Raw: "PUNPCKLBW Y0, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong src class", false},
		{"PSHUFHW", asm.Instr{Raw: "PSHUFHW $1, X0, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst", false},
		{"SHUFPS", asm.Instr{Raw: "SHUFPS $1, X0, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst", false},
		{"MOVOU", asm.Instr{Raw: "MOVOU AX, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong src class", true},
		{"MOVOU", asm.Instr{Raw: "MOVOU X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "wrong dst class", false},
		{"PXOR", asm.Instr{Raw: "PXOR X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "short form", true},
		{"PADDL", asm.Instr{Raw: "PADDL X0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "wrong dst class", false},
		{"PSLLL", asm.Instr{Raw: "PSLLL AX, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "non-imm shift", true},
		{"PCMPEQL", asm.Instr{Raw: "PCMPEQL Y0, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong src class", false},
		{"VPCLMULQDQ", asm.Instr{Raw: "VPCLMULQDQ $1, Z0, Z1, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong dst class", false},
		{"VPTERNLOGD", asm.Instr{Raw: "VPTERNLOGD $0x95, Z0, Z1, Z2", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x95}, {Kind: asm.OpReg, Reg: asm.Reg("Z0")}, {Kind: asm.OpReg, Reg: asm.Reg("Z1")}, {Kind: asm.OpReg, Reg: asm.Reg("Z2")}}}, "delegate non-0x96 imm", false},
		{"VEXTRACTF32X4", asm.Instr{Raw: "VEXTRACTF32X4 $1, X0, X1", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}}, "wrong src class", false},
		{"PCLMULQDQ", asm.Instr{Raw: "PCLMULQDQ AX, X0, X1", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.Reg("X1")}}}, "missing imm", true},
		{"PCMPEQB", asm.Instr{Raw: "PCMPEQB Y0, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong src class", false},
		{"PMOVMSKB", asm.Instr{Raw: "PMOVMSKB Y0, AX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.AX}}}, "wrong src class", false},
		{"PSHUFB", asm.Instr{Raw: "PSHUFB Y0, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong mask class", true},
		{"PINSRQ", asm.Instr{Raw: "PINSRQ AX, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "short form", true},
		{"PINSRD", asm.Instr{Raw: "PINSRD $1, AX, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst class", false},
		{"PINSRW", asm.Instr{Raw: "PINSRW $1, AX, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst class", false},
		{"PINSRB", asm.Instr{Raw: "PINSRB $1, AX, Y0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}}}, "wrong dst class", false},
		{"PEXTRB", asm.Instr{Raw: "PEXTRB AX, X0, BX", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpReg, Reg: asm.BX}}}, "missing imm", true},
		{"PALIGNR", asm.Instr{Raw: "PALIGNR $1, Y0, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("Y0")}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "wrong src class", false},
		{"PSRLDQ", asm.Instr{Raw: "PSRLDQ $17, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 17}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "invalid imm", true},
		{"PSLLDQ", asm.Instr{Raw: "PSLLDQ $17, X0", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 17}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "invalid imm", true},
		{"PSRLQ", asm.Instr{Raw: "PSRLQ AX, X0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}}}, "non-imm shift", true},
		{"PEXTRD", asm.Instr{Raw: "PEXTRD $1, X0, label", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpReg, Reg: asm.Reg("X0")}, {Kind: asm.OpIdent, Ident: "label"}}}, "bad dst kind", true},
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

func TestAMD64CtxAliasAndFPFallbackCoverage(t *testing.T) {
	sig := asm.FuncSig{
		Name: "example.ctxfallback",
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I1, Index: 0},
				{Offset: 16, Type: asm.I8, Index: 1},
				{Offset: 24, Type: asm.I16, Index: 2},
				{Offset: 32, Type: asm.I32, Index: 3},
				{Offset: 40, Type: asm.I64, Index: 4},
				{Offset: 48, Type: asm.Ptr, Index: 5},
			},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)

	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AX, "255"},
		{asm.BX, "511"},
		{asm.CX, "1023"},
		{asm.DX, "2047"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	for _, tc := range []struct {
		r  asm.Reg
		ty asm.LLVMType
		v  string
	}{
		{asm.BX, asm.I8, "37"},
		{asm.CX, asm.I16, "38"},
		{asm.DX, asm.I32, "39"},
	} {
		if err := c.storeRegSized(tc.r, tc.ty, tc.v); err != nil {
			t.Fatalf("storeRegSized(%s, %s) error = %v", tc.r, tc.ty, err)
		}
	}
	for _, r := range []asm.Reg{asm.AL, asm.AH, asm.BL, asm.BH, asm.CL, asm.CH, asm.DL, asm.DH} {
		if got, err := c.loadReg(r); err != nil || got == "" {
			t.Fatalf("loadReg(%s) = (%q, %v)", r, got, err)
		}
	}
	if got, err := c.loadReg(asm.Reg("MISSING")); err != nil || got != "0" {
		t.Fatalf("loadReg(MISSING) = (%q, %v)", got, err)
	}
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{asm.AL, "17"},
		{asm.AH, "33"},
		{asm.BL, "18"},
		{asm.BH, "34"},
		{asm.CL, "19"},
		{asm.CH, "35"},
		{asm.DL, "20"},
		{asm.DH, "36"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	if err := c.storeReg(asm.Reg("MISSING"), "21"); err != nil {
		t.Fatalf("storeReg(MISSING) error = %v", err)
	}

	for _, tc := range []struct {
		off int64
		ty  asm.LLVMType
		val string
	}{
		{8, asm.I1, "1"},
		{16, asm.I8, "2"},
		{24, asm.I16, "3"},
		{32, asm.I32, "4"},
		{40, asm.I64, "5"},
		{48, asm.I64, "6"},
	} {
		if err := c.storeFPResult(tc.off, tc.ty, tc.val); err != nil {
			t.Fatalf("storeFPResult(%d, %s) error = %v", tc.off, tc.ty, err)
		}
	}
	for _, tc := range []struct {
		off int64
		ty  asm.LLVMType
		val string
	}{
		{8, asm.I64, "7"},
		{32, asm.I16, "8"},
		{40, asm.LLVMType("double"), "%dbl"},
	} {
		if err := c.storeFPResult(tc.off, tc.ty, tc.val); err != nil {
			t.Fatalf("storeFPResult(extra %d, %s) error = %v", tc.off, tc.ty, err)
		}
	}
	if err := c.storeFPResult(40, asm.Ptr, "%arg0"); err != nil {
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

func TestAMD64EvalI64Coverage(t *testing.T) {
	sig := asm.FuncSig{
		Name: "example.eval",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.I64,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	if err := c.storeReg(asm.AX, "17"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	if err := c.storeReg(asm.BX, "128"); err != nil {
		t.Fatalf("storeReg(BX) error = %v", err)
	}

	if got, err := c.evalI64(asm.Operand{Kind: asm.OpImm, Imm: 7}); err != nil || got != "7" {
		t.Fatalf("evalI64(imm) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}); err != nil || got == "" {
		t.Fatalf("evalI64(reg) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpFP, FPOffset: 0}); err != nil || got == "" {
		t.Fatalf("evalI64(fp) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.BX, Off: 8}}); err != nil || got == "" {
		t.Fatalf("evalI64(mem) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpSym, Sym: "value<>(SB)"}); err != nil || got == "" {
		t.Fatalf("evalI64(sym) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpSym, Sym: "$value<>(SB)"}); err != nil || got == "" {
		t.Fatalf("evalI64(addr sym) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(asm.Operand{Kind: asm.OpSym, Sym: "bad sym"}); err != nil || got != "0" {
		t.Fatalf("evalI64(unresolved bare sym) = (%q, %v)", got, err)
	}
	if _, err := c.evalI64(asm.Operand{Kind: asm.OpLabel, Sym: "loop"}); err == nil {
		t.Fatalf("evalI64(label) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"load i64, ptr %reg_AX",
		"load i64, ptr %t",
		"load i64, ptr @\"example.value\"",
		"ptrtoint ptr @\"example.value\" to i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestAMD64VectorLoweringBranchCoverage(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.vectorEdges", Ret: asm.Void}, nil)
	imm := func(v int64) asm.Operand { return asm.Operand{Kind: asm.OpImm, Imm: v} }
	reg := func(r string) asm.Operand { return asm.Operand{Kind: asm.OpReg, Reg: asm.Reg(r)} }
	ident := func(name string) asm.Operand { return asm.Operand{Kind: asm.OpIdent, Ident: name} }
	sym := func(name string) asm.Operand { return asm.Operand{Kind: asm.OpSym, Sym: name} }
	mem := func(base string) asm.Operand {
		return asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: asm.Reg(base)}}
	}
	check := func(name string, op asm.Op, ins asm.Instr, wantErr bool, wantOK bool) {
		t.Helper()
		ok, _, err := c.lowerVec(op, ins)
		if wantErr && err == nil {
			t.Fatalf("%s: lowerVec(%s) error = nil", name, op)
		}
		if !wantErr && err != nil {
			t.Fatalf("%s: lowerVec(%s) error = %v", name, op, err)
		}
		if ok != wantOK {
			t.Fatalf("%s: lowerVec(%s) ok = %v, want %v", name, op, ok, wantOK)
		}
	}

	check("gf2-z-source-class", "VGF2P8AFFINEQB", asm.Instr{Args: []asm.Operand{imm(0), reg("Z0"), reg("X1"), reg("Z2")}}, false, false)
	check("gf2-z-source-error", "VGF2P8AFFINEQB", asm.Instr{Args: []asm.Operand{imm(0), reg("Z0"), ident("bad"), reg("Z2")}}, true, true)
	check("gf2-y-source-class", "VGF2P8AFFINEQB", asm.Instr{Args: []asm.Operand{imm(0), reg("Y0"), reg("X1"), reg("Y2")}}, false, false)
	check("gf2-y-source-error", "VGF2P8AFFINEQB", asm.Instr{Args: []asm.Operand{imm(0), reg("Y0"), ident("bad"), reg("Y2")}}, true, true)
	check("gf2-unsupported-dst", "VGF2P8AFFINEQB", asm.Instr{Args: []asm.Operand{imm(0), reg("Y0"), reg("Y1"), reg("X2")}}, false, false)

	check("broadcast-i128-args", "VBROADCASTI128", asm.Instr{Args: []asm.Operand{reg("X0")}}, true, true)
	check("broadcast-i128-dst", "VBROADCASTI128", asm.Instr{Args: []asm.Operand{reg("X0"), reg("X1")}}, false, false)
	check("broadcast-i128-source", "VBROADCASTI128", asm.Instr{Args: []asm.Operand{ident("bad"), reg("Y1")}}, true, true)
	check("broadcast-scalar-args", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{imm(1)}}, true, true)
	check("broadcast-scalar-source", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{ident("bad"), reg("Y1")}}, true, true)
	check("broadcast-scalar-immediate", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{imm(1), reg("Y1")}}, false, false)
	check("broadcast-scalar-gpr", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{reg("AX"), reg("Y1")}}, false, false)
	check("broadcast-scalar-x-source", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{reg("X0"), reg("Y1")}}, false, true)
	check("broadcast-scalar-x-dst", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{reg("X0"), reg("X1")}}, false, false)
	check("broadcast-scalar-dst", "VBROADCASTSD", asm.Instr{Args: []asm.Operand{mem("AX"), reg("AX")}}, false, false)
	check("broadcast-q-x", "VPBROADCASTQ", asm.Instr{Args: []asm.Operand{reg("X0"), reg("X1")}}, false, true)
	check("broadcast-q-gpr", "VPBROADCASTQ", asm.Instr{Args: []asm.Operand{reg("AX"), reg("X1")}}, false, true)
	check("broadcast-q-immediate", "VPBROADCASTQ", asm.Instr{Args: []asm.Operand{imm(1), reg("X1")}}, false, false)
	check("broadcast-q-address", "VPBROADCASTQ", asm.Instr{Args: []asm.Operand{sym("$value(SB)"), reg("X1")}}, false, false)
	check("pmululq-args", "PMULULQ", asm.Instr{Args: []asm.Operand{reg("X0")}}, true, true)
	check("pmululq-dst", "PMULULQ", asm.Instr{Args: []asm.Operand{reg("X0"), reg("Y1")}}, false, false)
	check("pmululq-src", "PMULULQ", asm.Instr{Args: []asm.Operand{reg("Y0"), reg("X1")}}, false, false)
	check("pmululq-source-error", "PMULULQ", asm.Instr{Args: []asm.Operand{ident("bad"), reg("X1")}}, true, true)
	check("pmululq-memory", "PMULULQ", asm.Instr{Args: []asm.Operand{mem("AX"), reg("X1")}}, false, true)
	check("punpckllq-args", "PUNPCKLLQ", asm.Instr{Args: []asm.Operand{reg("X0")}}, true, true)
	check("punpckhlq-dst", "PUNPCKHLQ", asm.Instr{Args: []asm.Operand{reg("X0"), reg("Y1")}}, false, false)
	check("punpckllq-src", "PUNPCKLLQ", asm.Instr{Args: []asm.Operand{reg("Y0"), reg("X1")}}, false, false)
	check("punpckhlq-source-error", "PUNPCKHLQ", asm.Instr{Args: []asm.Operand{ident("bad"), reg("X1")}}, true, true)
	check("punpckllq-memory", "PUNPCKLLQ", asm.Instr{Args: []asm.Operand{mem("AX"), reg("X1")}}, false, true)

	check("xorpd-args", "VXORPD", asm.Instr{Args: []asm.Operand{reg("X0")}}, true, true)
	check("xorpd-z", "VXORPD", asm.Instr{Args: []asm.Operand{reg("Z0"), reg("Z1"), reg("Z2")}}, false, true)
	check("xorpd-z-source1", "VXORPD", asm.Instr{Args: []asm.Operand{ident("bad"), reg("Z1"), reg("Z2")}}, true, true)
	check("xorpd-z-source2", "VXORPD", asm.Instr{Args: []asm.Operand{reg("Z0"), ident("bad"), reg("Z2")}}, true, true)
	check("xorpd-y", "VXORPD", asm.Instr{Args: []asm.Operand{reg("Y0"), reg("Y1"), reg("Y2")}}, false, true)
	check("xorpd-y-source1", "VXORPD", asm.Instr{Args: []asm.Operand{ident("bad"), reg("Y1"), reg("Y2")}}, true, true)
	check("xorpd-y-source2", "VXORPD", asm.Instr{Args: []asm.Operand{reg("Y0"), ident("bad"), reg("Y2")}}, true, true)
	check("xorpd-x", "VXORPD", asm.Instr{Args: []asm.Operand{reg("X0"), reg("X1"), reg("X2")}}, false, true)
	check("xorpd-x-source1", "VXORPD", asm.Instr{Args: []asm.Operand{ident("bad"), reg("X1"), reg("X2")}}, true, true)
	check("xorpd-x-source2", "VXORPD", asm.Instr{Args: []asm.Operand{reg("X0"), ident("bad"), reg("X2")}}, true, true)
	check("xorpd-unsupported-dst", "VXORPD", asm.Instr{Args: []asm.Operand{reg("X0"), reg("X1"), reg("AX")}}, false, false)

	check("ternlog-y-source1-class", "VPTERNLOGD", asm.Instr{Args: []asm.Operand{imm(0x96), reg("X0"), reg("Y1"), reg("Y2")}}, false, false)
	check("ternlog-y-source2-class", "VPTERNLOGD", asm.Instr{Args: []asm.Operand{imm(0x96), reg("Y0"), reg("X1"), reg("Y2")}}, false, false)
	check("ternlog-y-imm", "VPTERNLOGD", asm.Instr{Args: []asm.Operand{imm(0x95), reg("Y0"), reg("Y1"), reg("Y2")}}, false, false)
	check("ternlog-y-source1", "VPTERNLOGD", asm.Instr{Args: []asm.Operand{imm(0x96), ident("bad"), reg("Y1"), reg("Y2")}}, true, true)
	check("ternlog-y-source2", "VPTERNLOGD", asm.Instr{Args: []asm.Operand{imm(0x96), reg("Y0"), ident("bad"), reg("Y2")}}, true, true)

	check("pextrq-args", "PEXTRQ", asm.Instr{Args: []asm.Operand{imm(0)}}, true, true)
	check("pextrq-source", "PEXTRQ", asm.Instr{Args: []asm.Operand{imm(0), reg("AX"), reg("BX")}}, false, false)
	check("pextrq-reg", "PEXTRQ", asm.Instr{Args: []asm.Operand{imm(0), reg("X0"), reg("AX")}}, false, true)
	check("pextrq-mem", "PEXTRQ", asm.Instr{Args: []asm.Operand{imm(0), reg("X0"), mem("BAD")}}, false, true)
	check("pextrq-dst", "PEXTRQ", asm.Instr{Args: []asm.Operand{imm(0), reg("X0"), ident("bad")}}, true, true)

	if got := llvmRepeatI8Mask(0, 3); got != "<i32 0, i32 0, i32 0>" {
		t.Fatalf("llvmRepeatI8Mask(0, 3) = %q", got)
	}
}

func TestTranslate386FUCOMIClearsSignedCondition(t *testing.T) {
	fn := asm.Func{Instrs: []asm.Instr{{
		Op:   "FUCOMI",
		Args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, {Kind: asm.OpReg, Reg: "F1"}},
	}}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, asm.FuncSig{Name: "example.fucomi", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	start := b.Len()
	ok, terminated, err := c.lowerX87("FUCOMI", fn.Instrs[0])
	if !ok || terminated || err != nil {
		t.Fatalf("lowerX87(FUCOMI) = (%v, %v, %v)", ok, terminated, err)
	}
	got := b.String()[start:]
	for _, want := range []string{"ptr %flags_z", "ptr %flags_cf", "store i1 false, ptr %flags_slt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FUCOMI lowering missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fcmp olt double") {
		t.Fatalf("FUCOMI incorrectly synthesized a signed-less flag:\n%s", got)
	}
}

func Test386LoweringEdgeCases(t *testing.T) {
	fn := asm.Func{Instrs: []asm.Instr{
		{Op: "FLD1"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: asm.AX}, {Kind: asm.OpReg, Reg: asm.BX}}},
	}}
	sig := asm.FuncSig{Name: "example.edges", Ret: asm.Void}
	var b strings.Builder
	c := newX86Ctx(&b, fn, sig, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	expectError := func(name string, lower func() (bool, bool, error)) {
		t.Helper()
		ok, terminated, err := lower()
		if !ok || terminated || err == nil {
			t.Fatalf("%s = (%v, %v, %v), want handled non-terminating error", name, ok, terminated, err)
		}
	}
	ident := asm.Operand{Kind: asm.OpIdent, Ident: "invalid"}
	imm := asm.Operand{Kind: asm.OpImm, Imm: 1}
	reg := asm.Operand{Kind: asm.OpReg, Reg: asm.AX}

	for _, test := range []struct {
		name string
		op   asm.Op
		args []asm.Operand
	}{
		{name: "ADCL operand count", op: "ADCL"},
		{name: "ADCL source", op: "ADCL", args: []asm.Operand{ident, reg}},
		{name: "ADCL destination", op: "ADCL", args: []asm.Operand{imm, ident}},
		{name: "ADDL source", op: "ADDL", args: []asm.Operand{ident, reg}},
		{name: "ADDL destination", op: "ADDL", args: []asm.Operand{imm, ident}},
		{name: "ADDB source", op: "ADDB", args: []asm.Operand{ident, reg}},
		{name: "ANDW operand count", op: "ANDW"},
		{name: "ANDW source", op: "ANDW", args: []asm.Operand{ident, reg}},
		{name: "ANDW destination", op: "ANDW", args: []asm.Operand{imm, ident}},
		{name: "SETEQ destination", op: "SETEQ", args: []asm.Operand{ident}},
		{name: "IMULL source", op: "IMULL", args: []asm.Operand{ident}},
		{name: "IMULL destination", op: "IMULL", args: []asm.Operand{imm, imm}},
		{name: "IMULL two-operand source", op: "IMULL", args: []asm.Operand{ident, reg}},
		{name: "IMUL3L destination", op: "IMUL3L", args: []asm.Operand{imm, reg, imm}},
		{name: "IMUL3L immediate", op: "IMUL3L", args: []asm.Operand{ident, reg, reg}},
		{name: "IMUL3L source", op: "IMUL3L", args: []asm.Operand{imm, ident, reg}},
		{name: "IMULL operand count", op: "IMULL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectError(test.name, func() (bool, bool, error) {
				return c.lowerArith(test.op, asm.Instr{Raw: test.name, Args: test.args})
			})
		})
	}

	for _, test := range []struct {
		name string
		op   asm.Op
		args []asm.Operand
	}{
		{name: "FMOVD source", op: "FMOVD", args: []asm.Operand{ident, {Kind: asm.OpReg, Reg: "F0"}}},
		{name: "FMOVDP source", op: "FMOVDP", args: []asm.Operand{ident, reg}},
		{name: "FMOVV source", op: "FMOVV", args: []asm.Operand{ident, {Kind: asm.OpReg, Reg: "F0"}}},
		{name: "FMOVVP source", op: "FMOVVP", args: []asm.Operand{ident, reg}},
		{name: "FDIVD source", op: "FDIVD", args: []asm.Operand{ident, {Kind: asm.OpReg, Reg: "F0"}}},
		{name: "FDIVD destination", op: "FDIVD", args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, ident}},
		{name: "FADDDP source", op: "FADDDP", args: []asm.Operand{ident, {Kind: asm.OpReg, Reg: "F0"}}},
		{name: "FADDDP destination", op: "FADDDP", args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, ident}},
		{name: "FLDCW source", op: "FLDCW", args: []asm.Operand{ident}},
		{name: "FUCOMI lhs", op: "FUCOMI", args: []asm.Operand{ident, {Kind: asm.OpReg, Reg: "F0"}}},
		{name: "FUCOMI rhs", op: "FUCOMI", args: []asm.Operand{{Kind: asm.OpReg, Reg: "F0"}, ident}},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectError(test.name, func() (bool, bool, error) {
				return c.lowerX87(test.op, asm.Instr{Raw: test.name, Args: test.args})
			})
		})
	}

	if _, err := c.amd64AtomicPtrFromMem(asm.MemRef{Segment: asm.FS}); err == nil {
		t.Fatal("segment-relative atomic destination unexpectedly succeeded")
	}
	if got := x86FrameTypeSize(asm.I16); got != 2 {
		t.Fatalf("x86FrameTypeSize(i16) = %d, want 2", got)
	}
	if got := x86FrameTypeSize(asm.LLVMType("{ i32, i32 }")); got != 16 {
		t.Fatalf("x86FrameTypeSize(aggregate) = %d, want 16", got)
	}
	if _, ok := amd64ParseX87Reg("F8"); ok {
		t.Fatal("amd64ParseX87Reg(F8) unexpectedly succeeded")
	}
}

func Test386LoweringErrorPaths(t *testing.T) {
	fn := asm.Func{Instrs: []asm.Instr{
		{Op: "FLD1"},
		{Op: "MOVL", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, {Kind: asm.OpReg, Reg: asm.AX}}},
	}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, asm.FuncSig{Name: "example.errors", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}

	badMem := asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Segment: asm.Reg("BAD")}}
	badSym := asm.Operand{Kind: asm.OpSym, Sym: "(SB)"}
	wantLowerError := func(name string, lower func() (bool, bool, error)) {
		t.Helper()
		ok, terminated, err := lower()
		if !ok || terminated || err == nil {
			t.Fatalf("%s = (%v, %v, %v), want handled non-terminating error", name, ok, terminated, err)
		}
	}

	if _, _, err := c.loadIntDestination(badMem, asm.I32); err == nil {
		t.Fatal("loadIntDestination with an invalid segment unexpectedly succeeded")
	}
	wantLowerError("PUSHL source", func() (bool, bool, error) {
		return c.lowerArith("PUSHL", asm.Instr{Raw: "PUSHL invalid", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "invalid"}}})
	})
	wantLowerError("POPL destination", func() (bool, bool, error) {
		return c.lowerArith("POPL", asm.Instr{Raw: "POPL 0(BAD)", Args: []asm.Operand{badMem}})
	})
	wantLowerError("SETEQ destination", func() (bool, bool, error) {
		return c.lowerArith("SETEQ", asm.Instr{Raw: "SETEQ 0(BAD)", Args: []asm.Operand{badMem}})
	})
	wantLowerError("CMPXCHG8B destination", func() (bool, bool, error) {
		return c.lowerAtomic("CMPXCHG8B", asm.Instr{Raw: "CMPXCHG8B 0(BAD)", Args: []asm.Operand{badMem}})
	})
	wantLowerError("vector memory destination", func() (bool, bool, error) {
		return c.lowerVec("MOVL", asm.Instr{Raw: "MOVL X0, 0(BAD)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, badMem}})
	})
	wantLowerError("vector symbol destination", func() (bool, bool, error) {
		return c.lowerVec("MOVL", asm.Instr{Raw: "MOVL X0, (SB)", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "X0"}, badSym}})
	})

	for _, test := range []struct {
		name  string
		store func(asm.Operand) error
	}{
		{name: "x87 double memory", store: func(dst asm.Operand) error { return c.storeX87F64(dst, "0.0") }},
		{name: "x87 word memory", store: func(dst asm.Operand) error { return c.storeX87I16(dst, "0") }},
		{name: "x87 integer memory", store: func(dst asm.Operand) error { return c.storeX87I64(dst, "0") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.store(badMem); err == nil {
				t.Fatal("invalid segment unexpectedly succeeded")
			}
			if err := test.store(badSym); err == nil {
				t.Fatal("invalid symbol unexpectedly succeeded")
			}
		})
	}
	if ok, terminated, err := c.lowerX87("NOP", asm.Instr{Raw: "NOP"}); ok || terminated || err != nil {
		t.Fatalf("lowerX87(NOP) = (%v, %v, %v), want unhandled", ok, terminated, err)
	}
	if _, err := c.evalIntSized(asm.Operand{Kind: asm.OpSym, Sym: "$(SB)"}, asm.I32); err == nil {
		t.Fatal("invalid symbolic address unexpectedly succeeded")
	}

	oldArch := c.goarch
	c.goarch = "amd64"
	wantLowerError("amd64 MOVL FP source", func() (bool, bool, error) {
		return c.lowerMov("MOVL", asm.Instr{Raw: "MOVL $1, ret+0(FP)", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 1}, {Kind: asm.OpFP, FPOffset: 0}}})
	})
	c.goarch = oldArch

	var fp strings.Builder
	fpCtx := newX86Ctx(&fp, asm.Func{}, asm.FuncSig{Name: "example.fp", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	fpCtx.fpParams[0] = asm.FrameSlot{Offset: 0, Type: asm.I64, Index: 9, Field: -1}
	fpCtx.fpParams[8] = asm.FrameSlot{Offset: 8, Type: asm.I32, Index: 0, Field: -1}
	if _, err := fpCtx.evalFPToI64(100); err != nil {
		t.Fatal(err)
	}
	if _, err := fpCtx.evalFPToI64(4); err == nil {
		t.Fatal("high-word read of an invalid frame parameter unexpectedly succeeded")
	}

	var result strings.Builder
	resultCtx := newX86Ctx(&result, asm.Func{}, asm.FuncSig{Name: "example.result", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	resultCtx.fpResults = []asm.FrameSlot{
		{Offset: 0, Type: asm.I64, Index: 0, Field: -1},
		{Offset: 8, Type: asm.I32, Index: 1, Field: -1},
	}
	resultCtx.fpResAllocaOff[0] = "%result0"
	resultCtx.fpResAllocaIdx[0] = "%result0"
	resultCtx.classicFrame = "%classic_frame"
	resultCtx.classicSize = 16
	if _, err := resultCtx.evalFPToI64(100); err != nil {
		t.Fatal(err)
	}
	if got, err := resultCtx.evalFPToI64(4); err != nil || got == "" {
		t.Fatalf("high-word result read = (%q, %v)", got, err)
	}
	ok, terminated, err := resultCtx.lowerArith("LEAL", asm.Instr{Raw: "LEAL ret+0(FP), AX", Args: []asm.Operand{{Kind: asm.OpFPAddr, FPOffset: 0}, {Kind: asm.OpReg, Reg: asm.AX}}})
	if !ok || terminated || err != nil {
		t.Fatalf("LEAL classic result address = (%v, %v, %v)", ok, terminated, err)
	}
}

func Test386FDirectiveDoesNotAllocateX87State(t *testing.T) {
	fn := asm.Func{Instrs: []asm.Instr{{Op: "FUNCDATA"}}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, asm.FuncSig{Name: "example.directive", Ret: asm.Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	if c.usedX87 || strings.Contains(b.String(), "%x87_") {
		t.Fatalf("non-x87 F-prefixed directive allocated x87 state:\n%s", b.String())
	}
}

func Test386RejectsInvalidClassicFrameIndex(t *testing.T) {
	var b strings.Builder
	c := newX86Ctx(&b, asm.Func{}, asm.FuncSig{
		Name: "example.badframe",
		Args: []asm.LLVMType{asm.I32},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{Params: []asm.FrameSlot{
			{Offset: 0, Type: asm.I32, Index: 1, Field: -1},
		}},
	}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err == nil || !strings.Contains(err.Error(), "invalid arg index 1") {
		t.Fatalf("emitEntryAllocas() error = %v, want invalid frame index", err)
	}
}

func TestAMD64Ignores386ControlInstructions(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.amd64", Ret: asm.Void}, nil)
	for _, op := range []asm.Op{"ADJSP", "CLD", "STD", "REP"} {
		args := []asm.Operand(nil)
		if op == "ADJSP" {
			args = []asm.Operand{{Kind: asm.OpImm, Imm: 8}}
		}
		terminated, err := c.lowerInstr(0, 0, asm.Instr{Op: op, Raw: string(op), Args: args}, nil, nil)
		if err != nil || terminated {
			t.Fatalf("lowerInstr(%s) = (%v, %v), want ignored instruction", op, terminated, err)
		}
	}
}
