package arm64

import (
	"fmt"
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

func newARM64CtxWithFuncForTest(t *testing.T, fn asm.Func, sig asm.FuncSig, sigs map[string]asm.FuncSig) (*arm64Ctx, *strings.Builder) {
	t.Helper()
	if sig.Name == "" {
		sig.Name = "example.f"
	}
	if sigs == nil {
		sigs = map[string]asm.FuncSig{}
	}
	var b strings.Builder
	c := newARM64Ctx(&b, fn, sig, testResolveSym("example"), sigs, false)
	if err := c.emitEntryAllocasAndArgInit(); err != nil {
		t.Fatalf("emitEntryAllocasAndArgInit() error = %v", err)
	}
	return c, &b
}

func arm64RegOp(r asm.Reg) asm.Operand { return asm.Operand{Kind: asm.OpReg, Reg: r} }

func arm64ImmOp(v int64) asm.Operand { return asm.Operand{Kind: asm.OpImm, Imm: v} }

func arm64IdentOp(s string) asm.Operand { return asm.Operand{Kind: asm.OpIdent, Ident: s} }

func arm64SymOp(s string) asm.Operand { return asm.Operand{Kind: asm.OpSym, Sym: s} }

func arm64FPOp(off int64) asm.Operand { return asm.Operand{Kind: asm.OpFP, FPOffset: off} }

func arm64MemOp(base asm.Reg, off int64) asm.Operand {
	return asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: base, Off: off}}
}

func arm64RegListOp(regs ...asm.Reg) asm.Operand {
	return asm.Operand{Kind: asm.OpRegList, RegList: regs}
}

func TestARM64FPVectorPairValidation(t *testing.T) {
	if idx, ok := arm64ParseFReg("F31"); !ok || idx != 31 {
		t.Fatalf("arm64ParseFReg(F31) = (%d, %v)", idx, ok)
	}
	for _, r := range []asm.Reg{"R0", "F32", "Fbad"} {
		if _, ok := arm64ParseFReg(r); ok {
			t.Fatalf("arm64ParseFReg(%s) unexpectedly succeeded", r)
		}
	}

	c, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.vecerrors", Ret: asm.Void}, nil)
	if ok, _, err := c.lowerVec("FLDPQ", false, asm.Instr{Raw: "FLDPQ"}); !ok || err == nil {
		t.Fatalf("invalid FLDPQ = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerVec("FLDPQ", false, asm.Instr{
		Raw:  "FLDPQ (BAD), (F0, F1)",
		Args: []asm.Operand{arm64MemOp("BAD", 0), arm64RegListOp("F0", "F1")},
	}); !ok || err == nil {
		t.Fatalf("FLDPQ with bad base = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerVec("FLDPQ", false, asm.Instr{
		Raw:  "FLDPQ (R1), (R0, R1)",
		Args: []asm.Operand{arm64MemOp("R1", 0), arm64RegListOp("R0", "R1")},
	}); !ok || err == nil {
		t.Fatalf("FLDPQ with GPR pair = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerVec("FLDPQ", false, asm.Instr{
		Raw:  "FLDPQ (R1), (F0, F1)",
		Args: []asm.Operand{arm64MemOp("R1", 0), arm64RegListOp("F0", "F1")},
	}); !ok || err == nil {
		t.Fatalf("FLDPQ without vector slots = (%v, %v)", ok, err)
	}

	for _, ins := range []asm.Instr{
		{Raw: "VMOVI"},
		{Raw: "VMOVI $256, V0.B16", Args: []asm.Operand{arm64ImmOp(256), arm64RegOp("V0.B16")}},
		{Raw: "VMOVI $1, V0.D2", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("V0.D2")}},
		{Raw: "VMOVI $1, V0.B8", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("V0.B8")}},
	} {
		if ok, _, err := c.lowerVec("VMOVI", false, ins); !ok || err == nil {
			t.Fatalf("invalid %q = (%v, %v)", ins.Raw, ok, err)
		}
	}
}

func mustLowerARM64(t *testing.T, kind string, ins asm.Instr, ok bool, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s %q error = %v", kind, ins.Raw, err)
	}
	if !ok {
		t.Fatalf("%s %q returned ok=false", kind, ins.Raw)
	}
}

func arm64TestEmitBr(c *arm64Ctx) arm64EmitBr {
	return func(target string) {
		fmt.Fprintf(c.b, "  br label %%%s\n", asm.LLVMBlockName(target))
	}
}

func arm64TestEmitCondBr(c *arm64Ctx) arm64EmitCondBr {
	return func(cond string, target string, fall string) error {
		cv, err := c.condValue(cond)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", cv, asm.LLVMBlockName(target), asm.LLVMBlockName(fall))
		return nil
	}
}

func TestARM64AtomicCoverage(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.atomic", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "1"},
		{"R1", "2"},
		{"R2", "3"},
		{"R3", "4"},
		{"R4", "5"},
		{"R5", "6"},
		{"R6", "7"},
		{"R7", "8"},
		{"R8", "9"},
		{"R9", "10"},
		{"R10", "1024"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	mem := arm64MemOp("R10", 32)
	for _, tc := range []asm.Instr{
		{Op: "LDARW", Args: []asm.Operand{mem, arm64RegOp("R0")}, Raw: "LDARW 32(R10), R0"},
		{Op: "LDARB", Args: []asm.Operand{mem, arm64RegOp("R1")}, Raw: "LDARB 32(R10), R1"},
		{Op: "LDAR", Args: []asm.Operand{mem, arm64RegOp("R2")}, Raw: "LDAR 32(R10), R2"},
		{Op: "LDAXRW", Args: []asm.Operand{mem, arm64RegOp("R3")}, Raw: "LDAXRW 32(R10), R3"},
		{Op: "LDAXRB", Args: []asm.Operand{mem, arm64RegOp("R4")}, Raw: "LDAXRB 32(R10), R4"},
		{Op: "LDAXR", Args: []asm.Operand{mem, arm64RegOp("R5")}, Raw: "LDAXR 32(R10), R5"},
		{Op: "STLRW", Args: []asm.Operand{arm64RegOp("R0"), mem}, Raw: "STLRW R0, 32(R10)"},
		{Op: "STLRB", Args: []asm.Operand{arm64RegOp("R1"), mem}, Raw: "STLRB R1, 32(R10)"},
		{Op: "STLR", Args: []asm.Operand{arm64RegOp("R2"), mem}, Raw: "STLR R2, 32(R10)"},
		{Op: "STLXRW", Args: []asm.Operand{arm64RegOp("R3"), mem, arm64RegOp("R6")}, Raw: "STLXRW R3, 32(R10), R6"},
		{Op: "STLXRB", Args: []asm.Operand{arm64RegOp("R4"), mem, arm64RegOp("R7")}, Raw: "STLXRB R4, 32(R10), R7"},
		{Op: "STLXR", Args: []asm.Operand{arm64RegOp("R5"), mem, arm64RegOp("R8")}, Raw: "STLXR R5, 32(R10), R8"},
		{Op: "SWPALB", Args: []asm.Operand{arm64RegOp("R0"), mem, arm64RegOp("R1")}, Raw: "SWPALB R0, 32(R10), R1"},
		{Op: "SWPALW", Args: []asm.Operand{arm64RegOp("R2"), mem, arm64RegOp("R3")}, Raw: "SWPALW R2, 32(R10), R3"},
		{Op: "SWPALD", Args: []asm.Operand{arm64RegOp("R4"), mem, arm64RegOp("R5")}, Raw: "SWPALD R4, 32(R10), R5"},
		{Op: "LDADDALW", Args: []asm.Operand{arm64RegOp("R0"), mem, arm64RegOp("R1")}, Raw: "LDADDALW R0, 32(R10), R1"},
		{Op: "LDADDALD", Args: []asm.Operand{arm64RegOp("R2"), mem, arm64RegOp("R3")}, Raw: "LDADDALD R2, 32(R10), R3"},
		{Op: "LDORALB", Args: []asm.Operand{arm64RegOp("R4"), mem, arm64RegOp("R5")}, Raw: "LDORALB R4, 32(R10), R5"},
		{Op: "LDORALW", Args: []asm.Operand{arm64RegOp("R6"), mem, arm64RegOp("R7")}, Raw: "LDORALW R6, 32(R10), R7"},
		{Op: "LDORALD", Args: []asm.Operand{arm64RegOp("R8"), mem, arm64RegOp("R9")}, Raw: "LDORALD R8, 32(R10), R9"},
		{Op: "LDCLRALB", Args: []asm.Operand{arm64RegOp("R0"), mem, arm64RegOp("R1")}, Raw: "LDCLRALB R0, 32(R10), R1"},
		{Op: "LDCLRALW", Args: []asm.Operand{arm64RegOp("R2"), mem, arm64RegOp("R3")}, Raw: "LDCLRALW R2, 32(R10), R3"},
		{Op: "LDCLRALD", Args: []asm.Operand{arm64RegOp("R4"), mem, arm64RegOp("R5")}, Raw: "LDCLRALD R4, 32(R10), R5"},
		{Op: "CASALW", Args: []asm.Operand{arm64RegOp("R6"), mem, arm64RegOp("R7")}, Raw: "CASALW R6, 32(R10), R7"},
		{Op: "CASALD", Args: []asm.Operand{arm64RegOp("R8"), mem, arm64RegOp("R9")}, Raw: "CASALD R8, 32(R10), R9"},
	} {
		ok, _, err := c.lowerAtomic(tc.Op, tc)
		mustLowerARM64(t, "lowerAtomic", tc, ok, err)
	}

	if ptr, err := c.atomicMemPtr(asm.MemRef{Base: "R10", Off: 48}); err != nil || ptr == "" {
		t.Fatalf("atomicMemPtr() = (%q, %v)", ptr, err)
	}
	if ty, align := arm64AtomicLoadStoreType("LDAXRB"); ty != asm.I64 || align != 8 {
		t.Fatalf("arm64AtomicLoadStoreType(LDAXRB) = (%s, %d)", ty, align)
	}
	if ty, align := arm64AtomicStoreExclusiveType("STLXRB"); ty != asm.I8 || align != 1 {
		t.Fatalf("arm64AtomicStoreExclusiveType(STLXRB) = (%s, %d)", ty, align)
	}
	if ty, err := arm64AtomicRMWType("LDCLRALW"); err != nil || ty != asm.I32 {
		t.Fatalf("arm64AtomicRMWType(LDCLRALW) = (%s, %v)", ty, err)
	}
	if _, err := arm64AtomicRMWType("BAD"); err == nil {
		t.Fatalf("arm64AtomicRMWType(BAD) unexpectedly succeeded")
	}
	if size, err := arm64AtomicTypeSize(asm.I64); err != nil || size != 8 {
		t.Fatalf("arm64AtomicTypeSize(I64) = (%d, %v)", size, err)
	}
	if _, err := arm64AtomicTypeSize(asm.Ptr); err == nil {
		t.Fatalf("arm64AtomicTypeSize(ptr) unexpectedly succeeded")
	}
	if got, err := c.atomicTruncFromI64("99", asm.I16); err != nil || got == "" {
		t.Fatalf("atomicTruncFromI64() = (%q, %v)", got, err)
	}
	if _, err := c.atomicTruncFromI64("99", asm.Ptr); err == nil {
		t.Fatalf("atomicTruncFromI64(ptr) unexpectedly succeeded")
	}
	if got, err := c.atomicExtendToI64("%x", asm.I8); err != nil || got == "" {
		t.Fatalf("atomicExtendToI64() = (%q, %v)", got, err)
	}
	if _, err := c.atomicExtendToI64("%x", asm.Ptr); err == nil {
		t.Fatalf("atomicExtendToI64(ptr) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"load atomic i32",
		"load atomic i8",
		"load atomic i64",
		"store atomic i32",
		"store atomic i8",
		"cmpxchg ptr",
		"atomicrmw xchg",
		"atomicrmw add",
		"atomicrmw or",
		"atomicrmw and",
		"phi i64",
		"store i1 false, ptr %exclusive_valid",
		"zext i8",
		"trunc i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64ArithmeticCoverage(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.arith", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "11"},
		{"R1", "12"},
		{"R2", "13"},
		{"R3", "14"},
		{"R4", "15"},
		{"R5", "16"},
		{"R6", "17"},
		{"R7", "18"},
		{"R8", "19"},
		{"R9", "20"},
		{"R10", "21"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	c.storeFlag(c.flagsCSlot, "true")
	c.flagsWritten = true

	for _, tc := range []asm.Instr{
		{Op: "MRS_TPIDR_R0", Raw: "MRS_TPIDR_R0"},
		{Op: "MRS", Args: []asm.Operand{arm64IdentOp("MIDR_EL1"), arm64RegOp("R1")}, Raw: "MRS MIDR_EL1, R1"},
		{Op: "MRS", Args: []asm.Operand{arm64IdentOp("TPIDR_EL0"), arm64RegOp("R2")}, Raw: "MRS TPIDR_EL0, R2"},
		{Op: "MSR", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("DIT")}, Raw: "MSR $1, DIT"},
		{Op: "MSR", Args: []asm.Operand{arm64RegOp("R3"), arm64IdentOp("TPIDR_EL0")}, Raw: "MSR R3, TPIDR_EL0"},
		{Op: "UBFX", Args: []asm.Operand{arm64ImmOp(4), arm64RegOp("R4"), arm64ImmOp(8), arm64RegOp("R5")}, Raw: "UBFX $4, R4, $8, R5"},
		{Op: "ADD", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R0")}, Raw: "ADD $2, R0"},
		{Op: "SUB", Args: []asm.Operand{arm64ImmOp(3), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "SUB $3, R1, R2"},
		{Op: "ADDS", Args: []asm.Operand{arm64ImmOp(4), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "ADDS $4, R2, R3"},
		{Op: "ADC", Args: []asm.Operand{arm64ImmOp(5), arm64RegOp("R3")}, Raw: "ADC $5, R3"},
		{Op: "ADCS", Args: []asm.Operand{arm64ImmOp(6), arm64RegOp("R3"), arm64RegOp("R4")}, Raw: "ADCS $6, R3, R4"},
		{Op: "SBC", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R4")}, Raw: "SBC $1, R4"},
		{Op: "SBCS", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R4"), arm64RegOp("R5")}, Raw: "SBCS $2, R4, R5"},
		{Op: "ADDW", Args: []asm.Operand{arm64ImmOp(7), arm64RegOp("R5"), arm64RegOp("R6")}, Raw: "ADDW $7, R5, R6"},
		{Op: "SUBW", Args: []asm.Operand{arm64ImmOp(3), arm64RegOp("R6")}, Raw: "SUBW $3, R6"},
		{Op: "AND", Args: []asm.Operand{arm64ImmOp(15), arm64RegOp("R6"), arm64RegOp("R7")}, Raw: "AND $15, R6, R7"},
		{Op: "ANDS", Args: []asm.Operand{arm64ImmOp(3), arm64RegOp("R7")}, Raw: "ANDS $3, R7"},
		{Op: "EOR", Args: []asm.Operand{arm64ImmOp(8), arm64RegOp("R7"), arm64RegOp("R8")}, Raw: "EOR $8, R7, R8"},
		{Op: "ORR", Args: []asm.Operand{arm64ImmOp(9), arm64RegOp("R8")}, Raw: "ORR $9, R8"},
		{Op: "ANDW", Args: []asm.Operand{arm64ImmOp(7), arm64RegOp("R8"), arm64RegOp("R9")}, Raw: "ANDW $7, R8, R9"},
		{Op: "EORW", Args: []asm.Operand{arm64ImmOp(5), arm64RegOp("R9")}, Raw: "EORW $5, R9"},
		{Op: "ORRW", Args: []asm.Operand{arm64ImmOp(6), arm64RegOp("R9"), arm64RegOp("R10")}, Raw: "ORRW $6, R9, R10"},
		{Op: "ANDSW", Args: []asm.Operand{arm64ImmOp(3), arm64RegOp("R10"), arm64RegOp("R0")}, Raw: "ANDSW $3, R10, R0"},
		{Op: "SUBS", Args: []asm.Operand{arm64ImmOp(4), arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "SUBS $4, R0, R1"},
		{Op: "BIC", Args: []asm.Operand{arm64ImmOp(8), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "BIC $8, R1, R2"},
		{Op: "BICW", Args: []asm.Operand{arm64ImmOp(8), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "BICW $8, R2, R3"},
		{Op: "MVN", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R4")}, Raw: "MVN R3, R4"},
		{Op: "MVNW", Args: []asm.Operand{arm64RegOp("R4"), arm64RegOp("R5")}, Raw: "MVNW R4, R5"},
		{Op: "CRC32B", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "CRC32B R0, R1"},
		{Op: "CRC32H", Args: []asm.Operand{arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "CRC32H R1, R2"},
		{Op: "CRC32W", Args: []asm.Operand{arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "CRC32W R2, R3"},
		{Op: "CRC32X", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R4")}, Raw: "CRC32X R3, R4"},
		{Op: "CRC32CB", Args: []asm.Operand{arm64RegOp("R4"), arm64RegOp("R5")}, Raw: "CRC32CB R4, R5"},
		{Op: "CRC32CH", Args: []asm.Operand{arm64RegOp("R5"), arm64RegOp("R6")}, Raw: "CRC32CH R5, R6"},
		{Op: "CRC32CW", Args: []asm.Operand{arm64RegOp("R6"), arm64RegOp("R7")}, Raw: "CRC32CW R6, R7"},
		{Op: "CRC32CX", Args: []asm.Operand{arm64RegOp("R7"), arm64RegOp("R8")}, Raw: "CRC32CX R7, R8"},
		{Op: "CMP", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "CMP R0, R1"},
		{Op: "CMPW", Args: []asm.Operand{arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "CMPW R1, R2"},
		{Op: "CMN", Args: []asm.Operand{arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "CMN R2, R3"},
		{Op: "NEG", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R4")}, Raw: "NEG R3, R4"},
		{Op: "MUL", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R4"), arm64RegOp("R5")}, Raw: "MUL $2, R4, R5"},
		{Op: "UMULH", Args: []asm.Operand{arm64RegOp("R5"), arm64RegOp("R6"), arm64RegOp("R7")}, Raw: "UMULH R5, R6, R7"},
		{Op: "MADD", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "MADD R0, R1, R2, R3"},
		{Op: "MSUB", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R4"), arm64RegOp("R5"), arm64RegOp("R6")}, Raw: "MSUB R3, R4, R5, R6"},
		{Op: "LSL", Args: []asm.Operand{arm64ImmOp(3), arm64RegOp("R6"), arm64RegOp("R7")}, Raw: "LSL $3, R6, R7"},
		{Op: "LSR", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R7"), arm64RegOp("R8")}, Raw: "LSR R0, R7, R8"},
		{Op: "LSLW", Args: []asm.Operand{arm64RegOp("R1"), arm64RegOp("R8"), arm64RegOp("R9")}, Raw: "LSLW R1, R8, R9"},
		{Op: "LSRW", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R9"), arm64RegOp("R10")}, Raw: "LSRW $2, R9, R10"},
		{Op: "ASR", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R9"), arm64RegOp("R10")}, Raw: "ASR $2, R9, R10"},
		{Op: "UDIV", Args: []asm.Operand{arm64RegOp("R2"), arm64RegOp("R10"), arm64RegOp("R0")}, Raw: "UDIV R2, R10, R0"},
		{Op: "EXTR", Args: []asm.Operand{arm64ImmOp(9), arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "EXTR $9, R0, R1, R2"},
		{Op: "RORW", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "RORW R3, R2, R3"},
		{Op: "RBIT", Args: []asm.Operand{arm64RegOp("R3"), arm64RegOp("R4")}, Raw: "RBIT R3, R4"},
		{Op: "CLZ", Args: []asm.Operand{arm64RegOp("R4"), arm64RegOp("R5")}, Raw: "CLZ R4, R5"},
		{Op: "REV", Args: []asm.Operand{arm64RegOp("R5"), arm64RegOp("R6")}, Raw: "REV R5, R6"},
	} {
		ok, _, err := c.lowerArith(tc.Op, tc)
		mustLowerARM64(t, "lowerArith", tc, ok, err)
	}

	if _, _, err := c.lowerArith("UBFX", asm.Instr{Op: "UBFX", Args: []asm.Operand{arm64ImmOp(63), arm64RegOp("R0"), arm64ImmOp(2), arm64RegOp("R1")}, Raw: "UBFX $63, R0, $2, R1"}); err == nil {
		t.Fatalf("invalid UBFX unexpectedly succeeded")
	}
	if got, err := c.condValue("GT"); err != nil || got == "" {
		t.Fatalf("condValue(GT) = (%q, %v)", got, err)
	}
	if got, err := c.condValue("LE"); err != nil || got == "" {
		t.Fatalf("condValue(LE) = (%q, %v)", got, err)
	}
	if got, err := c.condValue("HI"); err != nil || got == "" {
		t.Fatalf("condValue(HI) = (%q, %v)", got, err)
	}
	if got, err := c.condValue("MI"); err != nil || got == "" {
		t.Fatalf("condValue(MI) = (%q, %v)", got, err)
	}
	if got, err := c.condValue("PL"); err != nil || got == "" {
		t.Fatalf("condValue(PL) = (%q, %v)", got, err)
	}
	if _, err := (&arm64Ctx{}).condValue("EQ"); err == nil {
		t.Fatalf("condValue without flags unexpectedly succeeded")
	}
	if got := CanonicalSysReg("DIT"); got != "S3_3_C4_C2_5" {
		t.Fatalf("arm64CanonicalSysReg(DIT) = %q", got)
	}
	if v, ok := CompileSafeMRSValue("MIDR_EL1"); !ok || v != "0" {
		t.Fatalf("arm64CompileSafeMRSValue(MIDR_EL1) = (%q, %v)", v, ok)
	}
	if _, ok := CompileSafeMRSValue("TPIDR_EL0"); ok {
		t.Fatalf("arm64CompileSafeMRSValue(TPIDR_EL0) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		`asm sideeffect "mrs $0, TPIDR_EL0"`,
		`asm sideeffect "msr S3_3_C4_C2_5, $0"`,
		"lshr i64",
		"lshr i32",
		"shl i64",
		"ashr i64",
		"udiv i64",
		"mul i128",
		"call i64 @llvm.bitreverse.i64",
		"call i64 @llvm.ctlz.i64",
		"call i64 @llvm.bswap.i64",
		"@llvm.aarch64.crc32b",
		"@llvm.aarch64.crc32cx",
		"xor i32",
		"zext i32",
		"trunc i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64DataVectorAndBranchCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V2"), arm64RegOp("V3")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V4"), arm64RegOp("V5")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V6"), arm64RegOp("V7")}},
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "loop"}}},
			{Op: "NOP", Raw: "NOP"},
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "next"}}},
			{Op: "NOP", Raw: "NOP"},
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "done"}}},
			{Op: "NOP", Raw: "NOP"},
		},
	}
	sigs := map[string]asm.FuncSig{
		"example.helper": {Name: "example.helper", Ret: asm.I64},
		"example.sink": {
			Name:    "example.sink",
			Args:    []asm.LLVMType{asm.I1, asm.I8, asm.I16, asm.I32, asm.Ptr, asm.I64},
			ArgRegs: []asm.Reg{"R0", "R1", "R2", "R3", "R4", "R5"},
			Ret:     asm.Void,
		},
		"example.sameSig": {
			Name: "example.sameSig",
			Args: []asm.LLVMType{asm.I64, asm.I32, asm.I16, asm.I8},
			Ret:  asm.I64,
		},
	}
	sig := asm.FuncSig{
		Name: "example.mix",
		Args: []asm.LLVMType{asm.I64, asm.I32, asm.I16, asm.I8},
		Ret:  asm.I64,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 24, Type: asm.I64, Index: 0},
				{Offset: 32, Type: asm.I32, Index: 1},
				{Offset: 40, Type: asm.I16, Index: 2},
				{Offset: 48, Type: asm.I8, Index: 3},
			},
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I64, Index: 0},
				{Offset: 16, Type: asm.I64, Index: 1},
			},
		},
	}
	c, b := newARM64CtxWithFuncForTest(t, fn, sig, sigs)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "33"},
		{"R1", "34"},
		{"R2", "35"},
		{"R3", "36"},
		{"R4", "37"},
		{"R5", "38"},
		{"R6", "39"},
		{"R7", "40"},
		{"R8", "41"},
		{"R9", "42"},
		{"R10", "43"},
		{"R20", "2048"},
		{"R21", "4096"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	for _, tc := range []struct {
		op      asm.Op
		postInc bool
		ins     asm.Instr
		kind    string
	}{
		{"MOVD", false, asm.Instr{Op: "MOVD", Args: []asm.Operand{arm64ImmOp(99), arm64RegOp("R0")}, Raw: "MOVD $99, R0"}, "data"},
		{"MOVD", false, asm.Instr{Op: "MOVD", Args: []asm.Operand{arm64RegOp("R0"), arm64MemOp("R20", 0)}, Raw: "MOVD R0, (R20)"}, "data"},
		{"MOVD", false, asm.Instr{Op: "MOVD", Args: []asm.Operand{arm64RegOp("R1"), arm64FPOp(8)}, Raw: "MOVD R1, ret+8(FP)"}, "data"},
		{"MOVD", false, asm.Instr{Op: "MOVD", Args: []asm.Operand{arm64RegOp("R2"), arm64SymOp("ignored<>(SB)")}, Raw: "MOVD R2, ignored<>(SB)"}, "data"},
		{"MOVB", false, asm.Instr{Op: "MOVB", Args: []asm.Operand{arm64MemOp("R20", 1), arm64RegOp("R2")}, Raw: "MOVB 1(R20), R2"}, "data"},
		{"MOVB", false, asm.Instr{Op: "MOVB", Args: []asm.Operand{arm64RegOp("R2"), arm64MemOp("R20", 2)}, Raw: "MOVB R2, 2(R20)"}, "data"},
		{"MOVB", false, asm.Instr{Op: "MOVB", Args: []asm.Operand{arm64RegOp("R2"), arm64FPOp(16)}, Raw: "MOVB R2, ret+16(FP)"}, "data"},
		{"MOVW", false, asm.Instr{Op: "MOVW", Args: []asm.Operand{arm64MemOp("R20", 4), arm64RegOp("R3")}, Raw: "MOVW 4(R20), R3"}, "data"},
		{"MOVW", false, asm.Instr{Op: "MOVW", Args: []asm.Operand{arm64RegOp("R3"), arm64MemOp("R20", 8)}, Raw: "MOVW R3, 8(R20)"}, "data"},
		{"MOVW", false, asm.Instr{Op: "MOVW", Args: []asm.Operand{arm64RegOp("R3"), arm64FPOp(8)}, Raw: "MOVW R3, ret+8(FP)"}, "data"},
		{"MOVH", false, asm.Instr{Op: "MOVH", Args: []asm.Operand{arm64MemOp("R20", 12), arm64RegOp("R4")}, Raw: "MOVH 12(R20), R4"}, "data"},
		{"MOVHU", false, asm.Instr{Op: "MOVHU", Args: []asm.Operand{arm64MemOp("R20", 14), arm64RegOp("R5")}, Raw: "MOVHU 14(R20), R5"}, "data"},
		{"MOVHU", false, asm.Instr{Op: "MOVHU", Args: []asm.Operand{arm64RegOp("R5"), arm64MemOp("R20", 16)}, Raw: "MOVHU R5, 16(R20)"}, "data"},
		{"MOVWU", false, asm.Instr{Op: "MOVWU", Args: []asm.Operand{arm64FPOp(32), arm64RegOp("R6")}, Raw: "MOVWU arg+32(FP), R6"}, "data"},
		{"MOVWU", true, asm.Instr{Op: "MOVWU.P", Args: []asm.Operand{arm64RegOp("R6"), arm64MemOp("R20", 4)}, Raw: "MOVWU.P R6, 4(R20)"}, "data"},
		{"MOVWU", false, asm.Instr{Op: "MOVWU", Args: []asm.Operand{arm64RegOp("R6"), arm64FPOp(16)}, Raw: "MOVWU R6, ret+16(FP)"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64MemOp("R20", 18), arm64RegOp("R7")}, Raw: "MOVBU 18(R20), R7"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64FPOp(48), arm64RegOp("R8")}, Raw: "MOVBU arg+48(FP), R8"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64SymOp("example.global(SB)"), arm64RegOp("R9")}, Raw: "MOVBU example.global(SB), R9"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64RegOp("R9"), arm64RegOp("R10")}, Raw: "MOVBU R9, R10"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64RegOp("R10"), arm64MemOp("R20", 20)}, Raw: "MOVBU R10, 20(R20)"}, "data"},
		{"MOVBU", false, asm.Instr{Op: "MOVBU", Args: []asm.Operand{arm64RegOp("R10"), arm64FPOp(16)}, Raw: "MOVBU R10, ret+16(FP)"}, "data"},
		{"LDP", true, asm.Instr{Op: "LDP.P", Args: []asm.Operand{arm64MemOp("R20", 16), arm64RegListOp("R0", "R1")}, Raw: "LDP.P 16(R20), [R0, R1]"}, "data"},
		{"LDP", false, asm.Instr{Op: "LDP", Args: []asm.Operand{arm64FPOp(24), arm64RegListOp("R2", "R3")}, Raw: "LDP arg+24(FP), [R2, R3]"}, "data"},
		{"LDP", false, asm.Instr{Op: "LDP", Args: []asm.Operand{arm64SymOp("example.global(SB)"), arm64RegListOp("R4", "R5")}, Raw: "LDP example.global(SB), [R4, R5]"}, "data"},
		{"LDPW", true, asm.Instr{Op: "LDPW.P", Args: []asm.Operand{arm64MemOp("R20", 8), arm64RegListOp("R6", "R7")}, Raw: "LDPW.P 8(R20), [R6, R7]"}, "data"},
		{"STPW", true, asm.Instr{Op: "STPW.P", Args: []asm.Operand{arm64RegListOp("R6", "R7"), arm64MemOp("R20", 8)}, Raw: "STPW.P [R6, R7], 8(R20)"}, "data"},
		{"STP", true, asm.Instr{Op: "STP.P", Args: []asm.Operand{arm64RegListOp("R8", "R9"), arm64MemOp("R20", 16)}, Raw: "STP.P [R8, R9], 16(R20)"}, "data"},
		{"VMOV", false, asm.Instr{Op: "VMOV", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("V0.B16")}, Raw: "VMOV R0, V0.B16"}, "vec"},
		{"VMOV", false, asm.Instr{Op: "VMOV", Args: []asm.Operand{arm64RegOp("R1"), arm64RegOp("V1.S4")}, Raw: "VMOV R1, V1.S4"}, "vec"},
		{"VMOV", false, asm.Instr{Op: "VMOV", Args: []asm.Operand{arm64RegOp("R2"), arm64RegOp("V2.D[1]")}, Raw: "VMOV R2, V2.D[1]"}, "vec"},
		{"VMOV", false, asm.Instr{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V2.D[1]"), arm64RegOp("R3")}, Raw: "VMOV V2.D[1], R3"}, "vec"},
		{"VMOV", false, asm.Instr{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V1"), arm64RegOp("V3")}, Raw: "VMOV V1, V3"}, "vec"},
		{"VEOR", false, asm.Instr{Op: "VEOR", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1"), arm64RegOp("V4")}, Raw: "VEOR V0, V1, V4"}, "vec"},
		{"VORR", false, asm.Instr{Op: "VORR", Args: []asm.Operand{arm64RegOp("V1"), arm64RegOp("V2"), arm64RegOp("V5")}, Raw: "VORR V1, V2, V5"}, "vec"},
		{"VLD1", true, asm.Instr{Op: "VLD1.P", Args: []asm.Operand{arm64MemOp("R21", 0), arm64RegOp("V4.B[3]")}, Raw: "VLD1.P (R21), V4.B[3]"}, "vec"},
		{"VLD1", true, asm.Instr{Op: "VLD1.P", Args: []asm.Operand{arm64MemOp("R21", 0), arm64RegListOp("V4", "V5", "V6", "V7")}, Raw: "VLD1.P (R21), [V4, V5, V6, V7]"}, "vec"},
		{"VST1", true, asm.Instr{Op: "VST1.P", Args: []asm.Operand{arm64RegListOp("V4", "V5"), arm64MemOp("R21", 0)}, Raw: "VST1.P [V4, V5], (R21)"}, "vec"},
		{"VCMEQ", false, asm.Instr{Op: "VCMEQ", Args: []asm.Operand{arm64RegOp("V4.B16"), arm64RegOp("V5.B16"), arm64RegOp("V6.B16")}, Raw: "VCMEQ V4.B16, V5.B16, V6.B16"}, "vec"},
		{"VCMEQ", false, asm.Instr{Op: "VCMEQ", Args: []asm.Operand{arm64RegOp("V4.D2"), arm64RegOp("V5.D2"), arm64RegOp("V7.D2")}, Raw: "VCMEQ V4.D2, V5.D2, V7.D2"}, "vec"},
		{"VAND", false, asm.Instr{Op: "VAND", Args: []asm.Operand{arm64RegOp("V4"), arm64RegOp("V5"), arm64RegOp("V6")}, Raw: "VAND V4, V5, V6"}, "vec"},
		{"VADDP", false, asm.Instr{Op: "VADDP", Args: []asm.Operand{arm64RegOp("V4.B16"), arm64RegOp("V5.B16"), arm64RegOp("V6.B16")}, Raw: "VADDP V4.B16, V5.B16, V6.B16"}, "vec"},
		{"VADDP", false, asm.Instr{Op: "VADDP", Args: []asm.Operand{arm64RegOp("V4.D2"), arm64RegOp("V5.D2"), arm64RegOp("V7.D2")}, Raw: "VADDP V4.D2, V5.D2, V7.D2"}, "vec"},
		{"VUADDLV", false, asm.Instr{Op: "VUADDLV", Args: []asm.Operand{arm64RegOp("V6.B16"), arm64RegOp("V7")}, Raw: "VUADDLV V6.B16, V7"}, "vec"},
		{"VADD", false, asm.Instr{Op: "VADD", Args: []asm.Operand{arm64RegOp("V4.S4"), arm64RegOp("V5.S4"), arm64RegOp("V6.S4")}, Raw: "VADD V4.S4, V5.S4, V6.S4"}, "vec"},
		{"VADD", false, asm.Instr{Op: "VADD", Args: []asm.Operand{arm64RegOp("V6.D2"), arm64RegOp("V7.D2")}, Raw: "VADD V6.D2, V7.D2"}, "vec"},
		{"AESE", false, asm.Instr{Op: "AESE", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1"), arm64RegOp("V2")}, Raw: "AESE V0, V1, V2"}, "vec"},
	} {
		switch tc.kind {
		case "data":
			ok, _, err := c.lowerData(tc.op, tc.postInc, tc.ins)
			mustLowerARM64(t, "lowerData", tc.ins, ok, err)
		case "vec":
			ok, _, err := c.lowerVec(tc.op, tc.postInc, tc.ins)
			mustLowerARM64(t, "lowerVec", tc.ins, ok, err)
		}
	}

	if kind, lane, ok := arm64ParseVRegLane("V0.B[15]"); !ok || kind != 'B' || lane != 15 {
		t.Fatalf("arm64ParseVRegLane(V0.B[15]) = (%q, %d, %v)", kind, lane, ok)
	}
	if _, _, ok := arm64ParseVRegLane("V0.X[0]"); ok {
		t.Fatalf("arm64ParseVRegLane(V0.X[0]) unexpectedly succeeded")
	}
	if got, ok := arm64BranchTarget(arm64IdentOp("loop")); !ok || got != "loop" {
		t.Fatalf("arm64BranchTarget(ident) = (%q, %v)", got, ok)
	}
	if got, ok := arm64BranchTarget(arm64SymOp("next<>(SB)")); !ok || got != "next" {
		t.Fatalf("arm64BranchTarget(sym) = (%q, %v)", got, ok)
	}
	if _, ok := arm64BranchTarget(arm64RegOp("R0")); ok {
		t.Fatalf("arm64BranchTarget(reg) unexpectedly succeeded")
	}
	if got := asm.LLVMBlockName("9.loop<>"); got != "bb_9_loop__" {
		t.Fatalf("arm64LLVMBlockName() = %q", got)
	}

	c.setFlagsSub("10", "4", "6")
	emitBr := arm64TestEmitBr(c)
	emitCondBr := arm64TestEmitCondBr(c)
	for _, tc := range []asm.Instr{
		{Op: "BL", Args: []asm.Operand{arm64RegOp("R0")}, Raw: "BL R0"},
		{Op: "CALL", Args: []asm.Operand{arm64MemOp("R20", 8)}, Raw: "CALL 8(R20)"},
		{Op: "BL", Args: []asm.Operand{arm64SymOp("helper(SB)")}, Raw: "BL helper(SB)"},
		{Op: "B", Args: []asm.Operand{arm64RegOp("R1")}, Raw: "B R1"},
		{Op: "JMP", Args: []asm.Operand{arm64MemOp("R20", 8)}, Raw: "JMP 8(R20)"},
		{Op: "B", Args: []asm.Operand{arm64SymOp("sink(SB)")}, Raw: "B sink(SB)"},
		{Op: "BEQ", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BEQ done"},
		{Op: "BNE", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BNE done"},
		{Op: "BLO", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BLO done"},
		{Op: "BHI", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BHI done"},
		{Op: "BHS", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BHS done"},
		{Op: "BLS", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BLS done"},
		{Op: "BLT", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BLT done"},
		{Op: "BGE", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BGE done"},
		{Op: "BGT", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BGT done"},
		{Op: "BLE", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BLE done"},
		{Op: "BCC", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BCC done"},
		{Op: "BCS", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BCS done"},
		{Op: "BMI", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BMI done"},
		{Op: "BPL", Args: []asm.Operand{arm64IdentOp("done")}, Raw: "BPL done"},
		{Op: "CBZ", Args: []asm.Operand{arm64RegOp("R2"), arm64IdentOp("done")}, Raw: "CBZ R2, done"},
		{Op: "CBNZ", Args: []asm.Operand{arm64RegOp("R3"), arm64MemOp(asm.PC, 4)}, Raw: "CBNZ R3, 4(PC)"},
		{Op: "TBZ", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R4"), arm64IdentOp("done")}, Raw: "TBZ $1, R4, done"},
		{Op: "TBNZ", Args: []asm.Operand{arm64ImmOp(2), arm64RegOp("R5"), arm64MemOp(asm.PC, 0)}, Raw: "TBNZ $2, R5, 0(PC)"},
		{Op: "CBZW", Args: []asm.Operand{arm64RegOp("R6"), arm64IdentOp("done")}, Raw: "CBZW R6, done"},
		{Op: "CBNZW", Args: []asm.Operand{arm64RegOp("R7"), arm64IdentOp("done")}, Raw: "CBNZW R7, done"},
	} {
		ok, _, err := c.lowerBranch(1, tc.Op, tc, emitBr, emitCondBr)
		mustLowerARM64(t, "lowerBranch", tc, ok, err)
	}

	if tgt, ok := c.resolveBranchTarget(1, arm64MemOp(asm.PC, -4)); !ok || tgt != c.blocks[1].name {
		t.Fatalf("resolveBranchTarget(-4(PC)) = (%q, %v)", tgt, ok)
	}
	if tgt, ok := c.resolveBranchTarget(1, arm64MemOp(asm.PC, 4)); !ok || tgt != c.blocks[2].name {
		t.Fatalf("resolveBranchTarget(4(PC)) = (%q, %v)", tgt, ok)
	}
	if got, err := c.castI64RegToArg("9", asm.I32); err != nil || got == "" {
		t.Fatalf("castI64RegToArg(i32) = (%q, %v)", got, err)
	}
	if got, err := c.castI64RegToArg("9", asm.Ptr); err != nil || got == "" {
		t.Fatalf("castI64RegToArg(ptr) = (%q, %v)", got, err)
	}
	if _, err := c.castI64RegToArg("9", asm.LLVMType("double")); err == nil {
		t.Fatalf("castI64RegToArg(double) unexpectedly succeeded")
	}
	cursor := 0
	if agg, err := c.structArgFromSequentialRegs(asm.LLVMType("{i32, i64}"), &cursor); err != nil || agg == "" || cursor != 2 {
		t.Fatalf("structArgFromSequentialRegs() = (%q, %d, %v)", agg, cursor, err)
	}
	if _, err := c.structArgFromSequentialRegs(asm.LLVMType("v2i64"), &cursor); err == nil {
		t.Fatalf("structArgFromSequentialRegs(v2i64) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("helper(SB)")); err != nil {
		t.Fatalf("callSym(helper) error = %v", err)
	}
	if err := c.callSym(arm64SymOp("runtime·entersyscall(SB)")); err != nil {
		t.Fatalf("callSym(runtime·entersyscall) error = %v", err)
	}
	if err := c.tailCallAndRet(arm64SymOp("sameSig(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(sameSig) error = %v", err)
	}
	if err := c.tailCallAndRet(arm64SymOp("sink(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(sink) error = %v", err)
	}

	out := b.String()
	for _, want := range []string{
		"store i64 99, ptr %reg_R0",
		"store i8",
		"store i16",
		"store i32",
		"load i64, ptr",
		"load <16 x i8>, ptr",
		"store <16 x i8>",
		"bitcast <16 x i8> ",
		"icmp eq <16 x i8>",
		"sext <16 x i1>",
		"call void asm sideeffect \"blr $0\"",
		"call void asm sideeffect \"br $0\"",
		`call i64 @"example.helper"()`,
		`call void @"example.sink"(`,
		"insertvalue {i32, i64}",
		"br i1",
		`call i64 @"example.sameSig"(i64 %arg0, i32 %arg1, i16 %arg2, i8 %arg3)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64FPOpsCoverage(t *testing.T) {
	sig := asm.FuncSig{
		Name: "example.fpops",
		Args: []asm.LLVMType{asm.LLVMType("double"), asm.LLVMType("float"), asm.I64, asm.I32, asm.I8, asm.Ptr},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.LLVMType("double"), Index: 0},
				{Offset: 8, Type: asm.LLVMType("float"), Index: 1},
				{Offset: 16, Type: asm.I64, Index: 2},
				{Offset: 24, Type: asm.I32, Index: 3},
				{Offset: 32, Type: asm.I8, Index: 4},
				{Offset: 40, Type: asm.Ptr, Index: 5},
			},
			Results: []asm.FrameSlot{
				{Offset: 48, Type: asm.I64, Index: 0},
				{Offset: 56, Type: asm.I64, Index: 1},
			},
		},
	}
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
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
		{"R0", "11"},
		{"R1", "12"},
		{"R2", "13"},
		{"R3", "14"},
		{"R4", "15"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	for _, ins := range []asm.Instr{
		{Op: "FMOVD", Args: []asm.Operand{arm64SymOp("$1.5"), arm64RegOp("R0")}, Raw: "FMOVD $1.5, R0"},
		{Op: "FMOVD", Args: []asm.Operand{arm64SymOp("$0x10"), arm64FPOp(48)}, Raw: "FMOVD $0x10, ret+48(FP)"},
		{Op: "FCMPD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R0")}, Raw: "FCMPD arg+0(FP), R0"},
		{Op: "FCSELD", Args: []asm.Operand{arm64IdentOp("EQ"), arm64FPOp(0), arm64FPOp(8), arm64RegOp("R1")}, Raw: "FCSELD EQ, arg+0(FP), arg+8(FP), R1"},
		{Op: "FADDD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R1")}, Raw: "FADDD arg+0(FP), R1"},
		{Op: "FSUBD", Args: []asm.Operand{arm64FPOp(8), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "FSUBD arg+8(FP), R1, R2"},
		{Op: "FMULD", Args: []asm.Operand{arm64FPOp(16), arm64RegOp("R2")}, Raw: "FMULD arg+16(FP), R2"},
		{Op: "FDIVD", Args: []asm.Operand{arm64FPOp(24), arm64RegOp("R2"), arm64FPOp(48)}, Raw: "FDIVD arg+24(FP), R2, ret+48(FP)"},
		{Op: "FMAXD", Args: []asm.Operand{arm64FPOp(32), arm64RegOp("R2")}, Raw: "FMAXD arg+32(FP), R2"},
		{Op: "FMIND", Args: []asm.Operand{arm64FPOp(40), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "FMIND arg+40(FP), R2, R3"},
		{Op: "FMADDD", Args: []asm.Operand{arm64FPOp(0), arm64FPOp(8), arm64FPOp(16), arm64RegOp("R3")}, Raw: "FMADDD arg+0(FP), arg+8(FP), arg+16(FP), R3"},
		{Op: "FMSUBD", Args: []asm.Operand{arm64FPOp(8), arm64FPOp(16), arm64FPOp(24), arm64RegOp("R4")}, Raw: "FMSUBD arg+8(FP), arg+16(FP), arg+24(FP), R4"},
		{Op: "FNMSUBD", Args: []asm.Operand{arm64FPOp(16), arm64FPOp(24), arm64FPOp(32), arm64FPOp(56)}, Raw: "FNMSUBD arg+16(FP), arg+24(FP), arg+32(FP), ret+56(FP)"},
		{Op: "FNMULD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R3")}, Raw: "FNMULD arg+0(FP), R3"},
		{Op: "FNMULD", Args: []asm.Operand{arm64FPOp(8), arm64FPOp(16), arm64RegOp("R4")}, Raw: "FNMULD arg+8(FP), arg+16(FP), R4"},
		{Op: "FABSD", Args: []asm.Operand{arm64RegOp("R4"), arm64FPOp(48)}, Raw: "FABSD R4, ret+48(FP)"},
		{Op: "FRINTZD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R0")}, Raw: "FRINTZD arg+0(FP), R0"},
		{Op: "FRINTMD", Args: []asm.Operand{arm64FPOp(8), arm64RegOp("R1")}, Raw: "FRINTMD arg+8(FP), R1"},
		{Op: "FRINTPD", Args: []asm.Operand{arm64FPOp(16), arm64FPOp(56)}, Raw: "FRINTPD arg+16(FP), ret+56(FP)"},
		{Op: "FCVTZSD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R2")}, Raw: "FCVTZSD arg+0(FP), R2"},
		{Op: "SCVTFD", Args: []asm.Operand{arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "SCVTFD R2, R3"},
	} {
		ok, _, err := c.lowerFP(ins.Op, ins)
		check("lowerFP", ins, ok, err)
	}

	if got, err := c.evalFMOVDBits(arm64SymOp("$2.5")); err != nil || got == "" {
		t.Fatalf("evalFMOVDBits($2.5) = (%q, %v)", got, err)
	}
	if got, err := c.evalFMOVDBits(arm64SymOp("$0x20")); err != nil || got != "32" {
		t.Fatalf("evalFMOVDBits($0x20) = (%q, %v)", got, err)
	}
	if got, err := c.evalF64(arm64RegOp("R0")); err != nil || got == "" {
		t.Fatalf("evalF64(reg) = (%q, %v)", got, err)
	}
	if got, err := c.evalF64(arm64ImmOp(3)); err != nil || got == "" {
		t.Fatalf("evalF64(imm) = (%q, %v)", got, err)
	}
	if got, err := c.evalF64(arm64SymOp("$4.5")); err != nil || got == "" {
		t.Fatalf("evalF64($4.5) = (%q, %v)", got, err)
	}
	for _, off := range []int64{0, 8, 16, 24, 32, 40} {
		if got, err := c.evalF64(arm64FPOp(off)); err != nil || got == "" {
			t.Fatalf("evalF64(+%d(FP)) = (%q, %v)", off, got, err)
		}
	}
	if _, err := c.evalF64(arm64SymOp("bad(SB)")); err == nil {
		t.Fatalf("evalF64(bad sym) unexpectedly succeeded")
	}
	if _, err := c.evalF64(arm64FPOp(99)); err == nil {
		t.Fatalf("evalF64(bad fp) unexpectedly succeeded")
	}
	if err := c.storeF64(arm64RegOp("R0"), "1.000000e+00"); err != nil {
		t.Fatalf("storeF64(reg) error = %v", err)
	}
	if err := c.storeF64(arm64FPOp(48), "2.000000e+00"); err != nil {
		t.Fatalf("storeF64(fp) error = %v", err)
	}
	if err := c.storeF64(arm64MemOp("R0", 0), "3.000000e+00"); err == nil {
		t.Fatalf("storeF64(mem) unexpectedly succeeded")
	}
	if got, ok := arm64ParseDollarFloat("$3.125"); !ok || got != 3.125 {
		t.Fatalf("arm64ParseDollarFloat() = (%v, %v)", got, ok)
	}
	if got, ok := arm64ParseDollarFloat("$1e3"); !ok || got != 1000 {
		t.Fatalf("arm64ParseDollarFloat($1e3) = (%v, %v)", got, ok)
	}
	for _, sym := range []string{"", "$", "3.125", "$10", "$nope"} {
		if _, ok := arm64ParseDollarFloat(sym); ok {
			t.Fatalf("arm64ParseDollarFloat(%q) unexpectedly succeeded", sym)
		}
	}
	if _, ok := arm64ParseDollarFloat("$0x10"); ok {
		t.Fatalf("arm64ParseDollarFloat($0x10) unexpectedly succeeded")
	}
	if got, ok := arm64ParseDollarInt64("$0x20"); !ok || got != 32 {
		t.Fatalf("arm64ParseDollarInt64() = (%d, %v)", got, ok)
	}
	if got, ok := arm64ParseDollarInt64("$18446744073709551615"); !ok || got != -1 {
		t.Fatalf("arm64ParseDollarInt64(uint64 max) = (%d, %v)", got, ok)
	}
	for _, sym := range []string{"", "$", "17", "$18446744073709551616"} {
		if _, ok := arm64ParseDollarInt64(sym); ok {
			t.Fatalf("arm64ParseDollarInt64(%q) unexpectedly succeeded", sym)
		}
	}
	if _, ok := arm64ParseDollarInt64("$1.5"); ok {
		t.Fatalf("arm64ParseDollarInt64($1.5) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"fcmp oeq double",
		"fcmp uno double",
		"select i1",
		"fadd double",
		"fsub double",
		"fmul double",
		"fdiv double",
		"fneg double",
		"@llvm.maxnum.f64",
		"@llvm.minnum.f64",
		"@llvm.fabs.f64",
		"@llvm.trunc.f64",
		"@llvm.floor.f64",
		"@llvm.ceil.f64",
		"fptosi double",
		"sitofp i64",
		"fpext float",
		"ptrtoint ptr",
		"bitcast i64",
		"bitcast double",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64BranchAndReturnEdgeCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: asm.OpTEXT, Raw: "TEXT ·edge(SB),NOSPLIT,$0-0"},
			{Op: "NOP", Raw: "NOP"},
		},
	}
	var translated strings.Builder
	if err := TranslateFunc(&translated, fn, asm.FuncSig{Name: "example.edge", Ret: asm.I64}, testResolveSym("example"), nil, true); err != nil {
		t.Fatalf("translateFuncARM64() error = %v", err)
	}
	if !strings.Contains(translated.String(), "ret i64 0") || !strings.Contains(translated.String(), "; s: NOP") {
		t.Fatalf("translateFuncARM64() output = \n%s", translated.String())
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
		c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, tc.sig, nil)
		if tc.sig.Ret != asm.Void {
			if err := c.storeReg("R0", "17"); err != nil {
				t.Fatalf("storeReg(R0) error = %v", err)
			}
		}
		if err := c.lowerRET(); err != nil {
			t.Fatalf("lowerRET(%s) error = %v", tc.name, err)
		}
		if !strings.Contains(b.String(), tc.want) {
			t.Fatalf("lowerRET(%s) output = \n%s", tc.name, b.String())
		}
	}

	cAgg, bAgg := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.retagg",
		Ret:  asm.LLVMType("{ i64, i32 }"),
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I64, Index: 0},
				{Offset: 16, Type: asm.I32, Index: 1},
			},
		},
	}, nil)
	if ok, _, err := cAgg.lowerData("MOVD", false, asm.Instr{
		Op:   "MOVD",
		Args: []asm.Operand{arm64ImmOp(21), arm64FPOp(8)},
		Raw:  "MOVD $21, ret+8(FP)",
	}); !ok || err != nil {
		t.Fatalf("lowerData(MOVD ret+8) = (%v, %v)", ok, err)
	}
	if ok, _, err := cAgg.lowerData("MOVW", false, asm.Instr{
		Op:   "MOVW",
		Args: []asm.Operand{arm64ImmOp(7), arm64FPOp(16)},
		Raw:  "MOVW $7, ret+16(FP)",
	}); !ok || err != nil {
		t.Fatalf("lowerData(MOVW ret+16) = (%v, %v)", ok, err)
	}
	if err := cAgg.lowerRET(); err != nil {
		t.Fatalf("lowerRET(aggregate) error = %v", err)
	}
	if !strings.Contains(bAgg.String(), "insertvalue { i64, i32 }") {
		t.Fatalf("lowerRET(aggregate) output = \n%s", bAgg.String())
	}

	cz, bz := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.zero", Ret: asm.I64}, nil)
	cz.lowerRetZero()
	if !strings.Contains(bz.String(), "ret i64 0") {
		t.Fatalf("lowerRetZero() output = \n%s", bz.String())
	}

	sigs := map[string]asm.FuncSig{
		"example.structSink": {Name: "example.structSink", Args: []asm.LLVMType{asm.LLVMType("{ i32, i64 }")}, Ret: asm.Void},
		"example.badarg":     {Name: "example.badarg", Args: []asm.LLVMType{asm.LLVMType("double")}, Ret: asm.Void},
		"example.badret":     {Name: "example.badret", Args: []asm.LLVMType{asm.I64}, Ret: asm.LLVMType("double")},
		"example.aggregate":  {Name: "example.aggregate", Ret: asm.LLVMType("{ ptr, i64 }")},
		"example.voidsame":   {Name: "example.voidsame", Args: []asm.LLVMType{asm.I64}, Ret: asm.Void},
		"example.badtailret": {Name: "example.badtailret", Args: []asm.LLVMType{asm.I64}, Ret: asm.LLVMType("double")},
	}
	cCalls, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.caller",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.I64,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.I64, Index: 0}},
		},
	}, sigs)
	if err := cCalls.storeReg("R0", "3"); err != nil {
		t.Fatalf("storeReg(R0) error = %v", err)
	}
	if err := cCalls.storeReg("R1", "4"); err != nil {
		t.Fatalf("storeReg(R1) error = %v", err)
	}
	if err := cCalls.callSym(arm64SymOp("unknown_helper(SB)")); err != nil {
		t.Fatalf("callSym(unknown) error = %v", err)
	}
	if err := cCalls.callSym(arm64SymOp("structSink(SB)")); err != nil {
		t.Fatalf("callSym(structSink) error = %v", err)
	}
	if err := cCalls.callSym(arm64SymOp("aggregate(SB)")); err != nil {
		t.Fatalf("callSym(aggregate) error = %v", err)
	}
	if err := cCalls.callSym(arm64SymOp("badarg(SB)")); err == nil {
		t.Fatalf("callSym(badarg) unexpectedly succeeded")
	}
	if err := cCalls.callSym(arm64SymOp("badret(SB)")); err == nil {
		t.Fatalf("callSym(badret) unexpectedly succeeded")
	}
	if err := cCalls.callSym(arm64RegOp("R0")); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := cCalls.callSym(arm64SymOp("broken")); err == nil {
		t.Fatalf("callSym(missing suffix) unexpectedly succeeded")
	}
	if err := cCalls.tailCallAndRet(arm64SymOp("missingTail(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(missing) error = %v", err)
	}
	cMismatch, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.mismatch", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, map[string]asm.FuncSig{
		"example.badtailret": {Name: "example.badtailret", Args: []asm.LLVMType{asm.I64}, Ret: asm.LLVMType("double")},
	})
	if err := cMismatch.storeReg("R0", "1"); err != nil {
		t.Fatalf("storeReg(R0) error = %v", err)
	}
	if err := cMismatch.tailCallAndRet(arm64SymOp("badtailret(SB)")); err == nil {
		t.Fatalf("tailCallAndRet(badtailret) unexpectedly succeeded")
	}
}

func TestARM64FPEdgeErrors(t *testing.T) {
	c, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.fperr",
		Args: []asm.LLVMType{asm.LLVMType("double"), asm.LLVMType("double")},
		Ret:  asm.LLVMType("double"),
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.LLVMType("double"), Index: 0},
				{Offset: 8, Type: asm.LLVMType("double"), Index: 1},
			},
			Results: []asm.FrameSlot{{Offset: 16, Type: asm.I64, Index: 0}},
		},
	}, nil)

	cases := []struct {
		op  asm.Op
		ins asm.Instr
	}{
		{"FMOVD", asm.Instr{Op: "FMOVD", Args: []asm.Operand{arm64SymOp("$1.5")}, Raw: "FMOVD $1.5"}},
		{"FMOVD", asm.Instr{Op: "FMOVD", Args: []asm.Operand{arm64SymOp("$1.5"), arm64MemOp("R0", 0)}, Raw: "FMOVD $1.5, 0(R0)"}},
		{"FCMPD", asm.Instr{Op: "FCMPD", Args: []asm.Operand{arm64FPOp(0)}, Raw: "FCMPD arg+0(FP)"}},
		{"FCSELD", asm.Instr{Op: "FCSELD", Args: []asm.Operand{arm64RegOp("R0"), arm64FPOp(0), arm64FPOp(8), arm64RegOp("R1")}, Raw: "FCSELD R0, arg+0(FP), arg+8(FP), R1"}},
		{"FADDD", asm.Instr{Op: "FADDD", Args: []asm.Operand{arm64FPOp(0)}, Raw: "FADDD arg+0(FP)"}},
		{"FMADDD", asm.Instr{Op: "FMADDD", Args: []asm.Operand{arm64FPOp(0), arm64FPOp(8), arm64RegOp("R0")}, Raw: "FMADDD arg+0(FP), arg+8(FP), R0"}},
		{"FNMULD", asm.Instr{Op: "FNMULD", Args: []asm.Operand{arm64FPOp(0)}, Raw: "FNMULD arg+0(FP)"}},
		{"FABSD", asm.Instr{Op: "FABSD", Args: []asm.Operand{arm64RegOp("R0")}, Raw: "FABSD R0"}},
		{"FRINTZD", asm.Instr{Op: "FRINTZD", Args: []asm.Operand{arm64FPOp(0)}, Raw: "FRINTZD arg+0(FP)"}},
		{"FCVTZSD", asm.Instr{Op: "FCVTZSD", Args: []asm.Operand{arm64FPOp(0), arm64FPOp(16)}, Raw: "FCVTZSD arg+0(FP), ret+16(FP)"}},
		{"SCVTFD", asm.Instr{Op: "SCVTFD", Args: []asm.Operand{arm64FPOp(0), arm64RegOp("R0")}, Raw: "SCVTFD arg+0(FP), R0"}},
	}
	for _, tc := range cases {
		if ok, term, err := c.lowerFP(tc.op, tc.ins); !ok || term || err == nil {
			t.Fatalf("lowerFP(%s %q) = (%v, %v, %v)", tc.op, tc.ins.Raw, ok, term, err)
		}
	}

	if got, err := c.evalFMOVDBits(arm64ImmOp(9)); err != nil || got != "9" {
		t.Fatalf("evalFMOVDBits(imm) = (%q, %v)", got, err)
	}
	if _, err := c.evalFMOVDBits(asm.Operand{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: "BAD", ShiftAmount: 1}); err == nil {
		t.Fatalf("evalFMOVDBits(bad shift) unexpectedly succeeded")
	}
}

func TestARM64SyscallCoverage(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.syscall", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "1"},
		{"R1", "2"},
		{"R2", "3"},
		{"R3", "4"},
		{"R4", "5"},
		{"R5", "6"},
		{"R8", "7"},
		{"R16", "8"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	if ok, term, err := c.lowerSyscall("SVC", asm.Instr{Raw: "SVC", Args: nil}); !ok || term || err != nil {
		t.Fatalf("lowerSyscall(linux) = (%v, %v, %v)", ok, term, err)
	}

	darwin, db := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.darwin", Ret: asm.Void}, nil)
	delete(darwin.regSlot, asm.Reg("R8"))
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "11"},
		{"R1", "12"},
		{"R2", "13"},
		{"R3", "14"},
		{"R4", "15"},
		{"R5", "16"},
		{"R16", "17"},
	} {
		if err := darwin.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("darwin storeReg(%s) error = %v", tc.r, err)
		}
	}
	if ok, term, err := darwin.lowerSyscall("SVC", asm.Instr{Raw: "SVC $0x80", Args: []asm.Operand{{Kind: asm.OpImm, Imm: 0x80}}}); !ok || term || err != nil {
		t.Fatalf("lowerSyscall(darwin) = (%v, %v, %v)", ok, term, err)
	}
	if _, _, err := c.lowerSyscall("SVC", asm.Instr{Raw: "SVC R0", Args: []asm.Operand{{Kind: asm.OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("bad SVC unexpectedly succeeded")
	}
	if ok, term, err := c.lowerSyscall("BAD", asm.Instr{}); ok || term || err != nil {
		t.Fatalf("lowerSyscall(BAD) = (%v, %v, %v)", ok, term, err)
	}

	out := b.String() + db.String()
	for _, want := range []string{
		"call i64 @syscall(i64 %t",
		"@cliteErrno()",
		"sub i64 0",
		"store i1 %t",
		"store i1 false, ptr %flags_v",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64ArithmeticErrorCoverage(t *testing.T) {
	c, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.aritherr", Ret: asm.Void}, nil)
	for _, tc := range []asm.Instr{
		{Op: "MRS", Raw: "MRS R0, R1", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1")}},
		{Op: "MSR", Raw: "MSR $1, R0", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0")}},
		{Op: "MSR", Raw: "MSR label, TPIDR_EL0", Args: []asm.Operand{{Kind: asm.OpIdent, Ident: "label"}, arm64IdentOp("TPIDR_EL0")}},
		{Op: "UBFX", Raw: "UBFX $1, R0, R1", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64RegOp("R1")}},
		{Op: "ADD", Raw: "ADD $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "ADD", Raw: "ADD $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "ADD", Raw: "ADD $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "ADC", Raw: "ADC $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "ADC", Raw: "ADC $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "ADC", Raw: "ADC $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "ADDW", Raw: "ADDW $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "ADDW", Raw: "ADDW $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "SUBW", Raw: "SUBW $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "AND", Raw: "AND $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "AND", Raw: "AND $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "AND", Raw: "AND $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "TSTW", Raw: "TSTW R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "ANDSW", Raw: "ANDSW $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "ANDSW", Raw: "ANDSW $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "ANDSW", Raw: "ANDSW $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "SUBS", Raw: "SUBS $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "SUBS", Raw: "SUBS $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "SUBS", Raw: "SUBS $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "SUBSW", Raw: "SUBSW $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "SUBSW", Raw: "SUBSW label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "SUBSW", Raw: "SUBSW $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "SUBSW", Raw: "SUBSW $1, label, R0", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "SUBSW", Raw: "SUBSW $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "BIC", Raw: "BIC $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "BIC", Raw: "BIC $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "BICW", Raw: "BICW $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "BICW", Raw: "BICW $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "MVN", Raw: "MVN $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "MVNW", Raw: "MVNW $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "CRC32B", Raw: "CRC32B $1, R0", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0")}},
		{Op: "CMP", Raw: "CMP R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "CMPW", Raw: "CMPW label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "CMPW", Raw: "CMPW R0, label", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "CMN", Raw: "CMN R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "CCMP", Raw: "CCMP", Args: nil},
		{Op: "CCMPW", Raw: "CCMPW EQ, R0, R1, $16", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0"), arm64RegOp("R1"), arm64ImmOp(16)}},
		{Op: "CCMN", Raw: "CCMN EQ, label, R1, $0", Args: []asm.Operand{arm64IdentOp("EQ"), arm64IdentOp("label"), arm64RegOp("R1"), arm64ImmOp(0)}},
		{Op: "CCMNW", Raw: "CCMNW BAD, R0, R1, $0", Args: []asm.Operand{arm64IdentOp("BAD"), arm64RegOp("R0"), arm64RegOp("R1"), arm64ImmOp(0)}},
		{Op: "NEG", Raw: "NEG R0, label", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "MULW", Raw: "MULW R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "MULW", Raw: "MULW label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "MULW", Raw: "MULW R0, label", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "MULW", Raw: "MULW R0, R1, label", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64IdentOp("label")}},
		{Op: "MULW", Raw: "MULW R0, label, R1", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label"), arm64RegOp("R1")}},
		{Op: "MUL", Raw: "MUL $1", Args: []asm.Operand{arm64ImmOp(1)}},
		{Op: "MUL", Raw: "MUL $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "MUL", Raw: "MUL $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "UMULH", Raw: "UMULH R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "MADDW", Raw: "MADDW R0, R1, R2", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2")}},
		{Op: "MADDW", Raw: "MADDW label, R1, R2, R3", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R1"), arm64RegOp("R2"), arm64RegOp("R3")}},
		{Op: "MADDW", Raw: "MADDW R0, label, R2, R3", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label"), arm64RegOp("R2"), arm64RegOp("R3")}},
		{Op: "MSUBW", Raw: "MSUBW R0, R1, label, R3", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64IdentOp("label"), arm64RegOp("R3")}},
		{Op: "MADD", Raw: "MADD R0, R1, R2", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2")}},
		{Op: "LSL", Raw: "LSL $64, R0", Args: []asm.Operand{arm64ImmOp(64), arm64RegOp("R0")}},
		{Op: "LSLW", Raw: "LSLW $32, R0", Args: []asm.Operand{arm64ImmOp(32), arm64RegOp("R0")}},
		{Op: "ASR", Raw: "ASR", Args: nil},
		{Op: "ASR", Raw: "ASR $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "ASR", Raw: "ASR $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "ASRW", Raw: "ASRW $32, R0", Args: []asm.Operand{arm64ImmOp(32), arm64RegOp("R0")}},
		{Op: "ASRW", Raw: "ASRW BAD, R0", Args: []asm.Operand{arm64RegOp("BAD"), arm64RegOp("R0")}},
		{Op: "ASR", Raw: "ASR $64, R0", Args: []asm.Operand{arm64ImmOp(64), arm64RegOp("R0")}},
		{Op: "ASR", Raw: "ASR label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "RORW", Raw: "RORW $32, R0", Args: []asm.Operand{arm64ImmOp(32), arm64RegOp("R0")}},
		{Op: "ROR", Raw: "ROR", Args: nil},
		{Op: "ROR", Raw: "ROR $1, label", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("label")}},
		{Op: "ROR", Raw: "ROR $1, R0, label", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("label")}},
		{Op: "ROR", Raw: "ROR $1, BAD", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("BAD")}},
		{Op: "ROR", Raw: "ROR $64, R0", Args: []asm.Operand{arm64ImmOp(64), arm64RegOp("R0")}},
		{Op: "ROR", Raw: "ROR label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "REVW", Raw: "REVW R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "REV16", Raw: "REV16 R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "REV32", Raw: "REV32 R0", Args: []asm.Operand{arm64RegOp("R0")}},
	} {
		if _, _, err := c.lowerArith(tc.Op, tc); err == nil {
			t.Fatalf("%s %q unexpectedly succeeded", tc.Op, tc.Raw)
		}
	}
	validBitfield := asm.Instr{Op: "BAD", Raw: "BAD $1, R0, $1, R1", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64ImmOp(1), arm64RegOp("R1")}}
	if err := c.lowerBitfield("BAD", validBitfield); err == nil {
		t.Fatal("unknown bitfield opcode unexpectedly succeeded")
	}
	if _, err := c.arm64InsertBits("i32", 32, "0", "0", 31, 2, 0); err == nil {
		t.Fatal("invalid bit insertion unexpectedly succeeded")
	}
}

func TestARM64Eval32Coverage(t *testing.T) {
	c, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.eval32", Ret: asm.Void}, nil)
	for _, op := range []asm.Operand{
		arm64ImmOp(-1),
		arm64RegOp("R0"),
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendUXTB},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendUXTH},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendUXTW},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendSXTB},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendSXTH},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendSXTW},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendUXTB, ShiftOp: asm.ShiftLeft, ShiftAmount: 2},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftLeft, ShiftAmount: 1},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftRight, ShiftAmount: 1},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftArith, ShiftAmount: 1},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftRotate, ShiftAmount: 1},
	} {
		if _, err := c.eval32(op); err != nil {
			t.Fatalf("eval32(%s) error = %v", op, err)
		}
	}
	for _, op := range []asm.Operand{
		{Kind: asm.OpReg, Reg: "BAD"},
		{Kind: asm.OpRegExtend, Reg: "BAD", Ext: asm.ExtendUXTB},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendOp("BAD")},
		{Kind: asm.OpRegExtend, Reg: "R0", Ext: asm.ExtendUXTB, ShiftOp: asm.ShiftRight, ShiftAmount: 1},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftLeft, ShiftReg: "R1"},
		{Kind: asm.OpRegShift, Reg: "BAD", ShiftOp: asm.ShiftLeft, ShiftAmount: 1},
		{Kind: asm.OpRegShift, Reg: "R0", ShiftOp: asm.ShiftOp("BAD"), ShiftAmount: 1},
		arm64IdentOp("label"),
	} {
		if _, err := c.eval32(op); err == nil {
			t.Fatalf("eval32(%s) unexpectedly succeeded", op)
		}
	}
}

func TestARM64NarrowMoveAndFMOVQErrorCoverage(t *testing.T) {
	fn := asm.Func{Instrs: []asm.Instr{
		{Op: "FMOVQ", Args: []asm.Operand{arm64MemOp("R1", 0), arm64RegOp("F0")}},
		{Op: "FMOVQ", Args: []asm.Operand{arm64RegOp("F0"), arm64MemOp("R1", 0)}},
	}}
	c, _ := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.newdataerrors", Ret: asm.Void}, nil)
	for _, ins := range []asm.Instr{
		{Op: "MOVKW", Raw: "MOVKW"},
		{Op: "MOVKW", Raw: "MOVKW $-1, R0", Args: []asm.Operand{arm64ImmOp(-1), arm64RegOp("R0")}},
		{Op: "MOVKW", Raw: "MOVKW $0x10001, R0", Args: []asm.Operand{arm64ImmOp(0x10001), arm64RegOp("R0")}},
		{Op: "MOVKW", Raw: "MOVKW $1, BAD", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("BAD")}},
	} {
		if _, _, err := c.lowerData("MOVKW", false, ins); err == nil {
			t.Fatalf("%q unexpectedly succeeded", ins.Raw)
		}
	}
	badIndex := asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R1", Index: "R2", Scale: 2}}
	for _, ins := range []asm.Instr{
		{Op: "FMOVQ", Raw: "FMOVQ"},
		{Op: "FMOVQ", Raw: "FMOVQ (R1), R0", Args: []asm.Operand{arm64MemOp("R1", 0), arm64RegOp("R0")}},
		{Op: "FMOVQ", Raw: "FMOVQ (R1)(R2<<1), F0", Args: []asm.Operand{badIndex, arm64RegOp("F0")}},
		{Op: "FMOVQ", Raw: "FMOVQ (R1), F31", Args: []asm.Operand{arm64MemOp("R1", 0), arm64RegOp("F31")}},
		{Op: "FMOVQ", Raw: "FMOVQ R0, (R1)", Args: []asm.Operand{arm64RegOp("R0"), arm64MemOp("R1", 0)}},
		{Op: "FMOVQ", Raw: "FMOVQ F31, (R1)", Args: []asm.Operand{arm64RegOp("F31"), arm64MemOp("R1", 0)}},
		{Op: "FMOVQ", Raw: "FMOVQ F0, (R1)(R2<<1)", Args: []asm.Operand{arm64RegOp("F0"), badIndex}},
		{Op: "FMOVQ", Raw: "FMOVQ R0, R1", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1")}},
	} {
		if _, _, err := c.lowerVec("FMOVQ", false, ins); err == nil {
			t.Fatalf("%q unexpectedly succeeded", ins.Raw)
		}
	}
	for _, tc := range []struct {
		op      asm.Operand
		preInc  bool
		postInc bool
	}{
		{arm64MemOp("R1", 0), true, true},
		{arm64SymOp("example.global(SB)"), true, false},
		{arm64IdentOp("label"), false, false},
		{badIndex, false, false},
		{arm64MemOp("BAD", 0), false, false},
	} {
		if _, _, _, _, err := c.arm64VectorMemoryPointer(tc.op, tc.preInc, tc.postInc); err == nil {
			t.Fatalf("arm64VectorMemoryPointer(%s, %v, %v) unexpectedly succeeded", tc.op, tc.preInc, tc.postInc)
		}
	}
	for _, ins := range []asm.Instr{
		{Op: "MOVW", Raw: "MOVW R0"},
		{Op: "MOVW", Raw: "MOVW $example.global(SB), R0", Args: []asm.Operand{arm64SymOp("$example.global(SB)"), arm64RegOp("R0")}},
		{Op: "MOVW", Raw: "MOVW BAD, R0", Args: []asm.Operand{arm64RegOp("BAD"), arm64RegOp("R0")}},
		{Op: "MOVW", Raw: "MOVW R0, broken symbol", Args: []asm.Operand{arm64RegOp("R0"), arm64SymOp("broken symbol")}},
		{Op: "MOVW", Raw: "MOVW R0, label", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("label")}},
	} {
		if err := c.lowerNarrowMove("MOVW", ins, 32, true, false); err == nil {
			t.Fatalf("%q unexpectedly succeeded", ins.Raw)
		}
	}
	if err := c.lowerNarrowMove("MOVW", asm.Instr{Op: "MOVW", Raw: "MOVW R0, example.global(SB)", Args: []asm.Operand{arm64RegOp("R0"), arm64SymOp("example.global(SB)")}}, 32, true, false); err != nil {
		t.Fatalf("narrow symbol store error = %v", err)
	}
}

func TestARM64VectorEdgeCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V2"), arm64RegOp("V3")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V4"), arm64RegOp("V5")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V6"), arm64RegOp("V7")}},
			{Op: "VMOV", Args: []asm.Operand{arm64RegOp("V8"), arm64RegOp("V9")}},
		},
	}
	c, b := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.vecedge", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "41"},
		{"R1", "42"},
		{"R2", "43"},
		{"R3", "44"},
		{"R4", "45"},
		{"R5", "46"},
		{"R20", "4096"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	check := func(op asm.Op, postInc bool, ins asm.Instr) {
		t.Helper()
		if ok, term, err := c.lowerVec(op, postInc, ins); !ok || term || err != nil {
			t.Fatalf("lowerVec(%s %q) = (%v, %v, %v)", op, ins.Raw, ok, term, err)
		}
	}

	check("VLD1R", false, asm.Instr{Op: "VLD1R", Raw: "VLD1R (R20), V0"})
	check("VMOV", false, asm.Instr{Op: "VMOV", Raw: "VMOV R0, V0.S4", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("V0.S4")}})
	check("VMOV", false, asm.Instr{Op: "VMOV", Raw: "VMOV V0.S[2], R3", Args: []asm.Operand{arm64RegOp("V0.S[2]"), arm64RegOp("R3")}})
	check("VMOV", false, asm.Instr{Op: "VMOV", Raw: "VMOV V1.H[4], R4", Args: []asm.Operand{arm64RegOp("V1.H[4]"), arm64RegOp("R4")}})
	check("VMOV", false, asm.Instr{Op: "VMOV", Raw: "VMOV V2.B[7], R5", Args: []asm.Operand{arm64RegOp("V2.B[7]"), arm64RegOp("R5")}})
	check("VMOV", false, asm.Instr{Op: "VMOV", Raw: "VMOV V2, R0", Args: []asm.Operand{arm64RegOp("V2"), arm64RegOp("R0")}})
	check("VLD1", true, asm.Instr{Op: "VLD1.P", Raw: "VLD1.P (R20), V3.D[1]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegOp("V3.D[1]")}})
	check("VLD1", true, asm.Instr{Op: "VLD1.P", Raw: "VLD1.P (R20), V4.S[1]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegOp("V4.S[1]")}})
	check("VLD1", true, asm.Instr{Op: "VLD1.P", Raw: "VLD1.P (R20), V5.H[3]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegOp("V5.H[3]")}})
	check("VLD1", true, asm.Instr{Op: "VLD1.P", Raw: "VLD1.P (R20), [V6]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegListOp("V6")}})
	check("VLD1", true, asm.Instr{Op: "VLD1.P", Raw: "VLD1.P (R20), [V7, V8, V9]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegListOp("V7", "V8", "V9")}})
	check("VST1", true, asm.Instr{Op: "VST1.P", Raw: "VST1.P [V0], (R20)", Args: []asm.Operand{arm64RegListOp("V0"), arm64MemOp("R20", 0)}})
	check("VST1", true, asm.Instr{Op: "VST1.P", Raw: "VST1.P [V1, V2, V3], (R20)", Args: []asm.Operand{arm64RegListOp("V1", "V2", "V3"), arm64MemOp("R20", 0)}})

	for _, tc := range []asm.Instr{
		{Op: "VMOV", Raw: "VMOV R0", Args: []asm.Operand{arm64RegOp("R0")}},
		{Op: "VMOV", Raw: "VMOV V0.Q[0], R0", Args: []asm.Operand{arm64RegOp("V0.Q[0]"), arm64RegOp("R0")}},
		{Op: "VMOV", Raw: "VMOV label, R0", Args: []asm.Operand{arm64IdentOp("label"), arm64RegOp("R0")}},
		{Op: "VEOR", Raw: "VEOR V0, V1", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
		{Op: "VORR", Raw: "VORR V0, V1", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
		{Op: "VLD1", Raw: "VLD1 (R20), V0", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegOp("V0")}},
		{Op: "VLD1", Raw: "VLD1 (R20), [V0,V1,V2,V3,V4]", Args: []asm.Operand{arm64MemOp("R20", 0), arm64RegListOp("V0", "V1", "V2", "V3", "V4")}},
		{Op: "VST1", Raw: "VST1 V0, (R20)", Args: []asm.Operand{arm64RegOp("V0"), arm64MemOp("R20", 0)}},
		{Op: "VST1", Raw: "VST1 [V0,V1,V2,V3,V4], (R20)", Args: []asm.Operand{arm64RegListOp("V0", "V1", "V2", "V3", "V4"), arm64MemOp("R20", 0)}},
		{Op: "VCMEQ", Raw: "VCMEQ V0, V1", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
		{Op: "VAND", Raw: "VAND V0, V1", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
		{Op: "VADDP", Raw: "VADDP V0, V1", Args: []asm.Operand{arm64RegOp("V0"), arm64RegOp("V1")}},
		{Op: "VUADDLV", Raw: "VUADDLV V0", Args: []asm.Operand{arm64RegOp("V0")}},
		{Op: "VADD", Raw: "VADD V0", Args: []asm.Operand{arm64RegOp("V0")}},
	} {
		if _, _, err := c.lowerVec(tc.Op, false, tc); err == nil {
			t.Fatalf("%s %q unexpectedly succeeded", tc.Op, tc.Raw)
		}
	}

	out := b.String()
	for _, want := range []string{
		"bitcast <16 x i8> ",
		"insertelement <8 x i16>",
		"insertelement <4 x i32>",
		"extractelement <8 x i16>",
		"extractelement <4 x i32>",
		"load i64, ptr %t",
		"load i32, ptr %t",
		"load i16, ptr %t",
		"load <16 x i8>, ptr",
		"store <16 x i8>",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64BranchErrorCoverage(t *testing.T) {
	fn := asm.Func{
		Instrs: []asm.Instr{
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "entry"}}},
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "fall"}}},
			{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: "done"}}},
		},
	}
	sigs := map[string]asm.FuncSig{
		"example.ret8":        {Name: "example.ret8", Args: []asm.LLVMType{asm.I64}, Ret: asm.I8},
		"example.retptr":      {Name: "example.retptr", Args: []asm.LLVMType{asm.I64}, Ret: asm.Ptr},
		"example.badarg":      {Name: "example.badarg", Args: []asm.LLVMType{asm.LLVMType("double")}, Ret: asm.Void},
		"example.badret":      {Name: "example.badret", Args: []asm.LLVMType{asm.I64}, Ret: asm.LLVMType("double")},
		"example.badagg":      {Name: "example.badagg", Args: []asm.LLVMType{asm.LLVMType("{ i32, double }")}, Ret: asm.Void},
		"example.badargreg":   {Name: "example.badargreg", Args: []asm.LLVMType{asm.I64}, ArgRegs: []asm.Reg{"BAD"}, Ret: asm.Void},
		"example.casttail":    {Name: "example.casttail", Args: []asm.LLVMType{asm.I32, asm.I64, asm.I64, asm.Ptr}, Ret: asm.I64},
		"example.badtailtype": {Name: "example.badtailtype", Args: []asm.LLVMType{asm.LLVMType("double")}, ArgRegs: []asm.Reg{"R0"}, Ret: asm.I64},
		"example.structtail":  {Name: "example.structtail", Args: []asm.LLVMType{asm.LLVMType("{ i32, i64 }")}, Ret: asm.I64},
		"example.badtailreg":  {Name: "example.badtailreg", Args: []asm.LLVMType{asm.LLVMType("double")}, ArgRegs: []asm.Reg{"BAD"}, Ret: asm.I64},
		"example.voidsink2":   {Name: "example.voidsink2", Args: []asm.LLVMType{asm.I64}, Ret: asm.Void},
		"example.nonvoid":     {Name: "example.nonvoid", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64},
	}
	sig := asm.FuncSig{Name: "example.brancherr", Args: []asm.LLVMType{asm.I64, asm.I8, asm.Ptr, asm.I64}, Ret: asm.I64}
	c, _ := newARM64CtxWithFuncForTest(t, fn, sig, sigs)
	c.blocks = []arm64Block{{name: "entry"}, {name: "fall"}, {name: "done"}}
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "11"},
		{"R1", "12"},
		{"R2", "13"},
		{"R3", "14"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	emitBr := arm64TestEmitBr(c)
	emitCondBr := arm64TestEmitCondBr(c)

	if tgt, ok := c.resolveBranchTarget(2, arm64MemOp(asm.PC, 4)); !ok || tgt != c.blocks[2].name {
		t.Fatalf("resolveBranchTarget(last,+4) = (%q, %v)", tgt, ok)
	}
	if tgt, ok := c.resolveBranchTarget(0, arm64MemOp(asm.PC, 0)); !ok || tgt != c.blocks[0].name {
		t.Fatalf("resolveBranchTarget(0(PC)) = (%q, %v)", tgt, ok)
	}
	if _, ok := c.resolveBranchTarget(0, arm64ImmOp(1)); ok {
		t.Fatalf("resolveBranchTarget($1) unexpectedly succeeded")
	}
	if ok, term, err := c.lowerBranch(1, "B", asm.Instr{Raw: "B 0(PC)", Args: []asm.Operand{arm64MemOp(asm.PC, 0)}}, emitBr, emitCondBr); !ok || term || err == nil {
		t.Fatalf("lowerBranch(B 0(PC)) = (%v, %v, %v), want error", ok, term, err)
	}

	errCases := []struct {
		name string
		run  func() error
	}{
		{"BL no args", func() error {
			_, _, err := c.lowerBranch(1, "BL", asm.Instr{Raw: "BL", Args: nil}, emitBr, emitCondBr)
			return err
		}},
		{"BL bad target", func() error {
			_, _, err := c.lowerBranch(1, "BL", asm.Instr{Raw: "BL $1", Args: []asm.Operand{arm64ImmOp(1)}}, emitBr, emitCondBr)
			return err
		}},
		{"B no args", func() error {
			_, _, err := c.lowerBranch(1, "B", asm.Instr{Raw: "B", Args: nil}, emitBr, emitCondBr)
			return err
		}},
		{"B bad target", func() error {
			_, _, err := c.lowerBranch(1, "B", asm.Instr{Raw: "B $1", Args: []asm.Operand{arm64ImmOp(1)}}, emitBr, emitCondBr)
			return err
		}},
		{"BEQ missing arg", func() error {
			_, _, err := c.lowerBranch(1, "BEQ", asm.Instr{Raw: "BEQ", Args: nil}, emitBr, emitCondBr)
			return err
		}},
		{"BEQ invalid target", func() error {
			_, _, err := c.lowerBranch(1, "BEQ", asm.Instr{Raw: "BEQ R0", Args: []asm.Operand{arm64RegOp("R0")}}, emitBr, emitCondBr)
			return err
		}},
		{"BEQ emit error", func() error {
			_, _, err := c.lowerBranch(1, "BEQ", asm.Instr{Raw: "BEQ done", Args: []asm.Operand{arm64IdentOp("done")}}, emitBr, func(string, string, string) error {
				return fmt.Errorf("emit cond failure")
			})
			return err
		}},
		{"CBZ bad args", func() error {
			_, _, err := c.lowerBranch(1, "CBZ", asm.Instr{Raw: "CBZ $1, done", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("done")}}, emitBr, emitCondBr)
			return err
		}},
		{"TBZ bad args", func() error {
			_, _, err := c.lowerBranch(1, "TBZ", asm.Instr{Raw: "TBZ R0, done", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("done")}}, emitBr, emitCondBr)
			return err
		}},
		{"CBZW bad args", func() error {
			_, _, err := c.lowerBranch(1, "CBZW", asm.Instr{Raw: "CBZW $1, done", Args: []asm.Operand{arm64ImmOp(1), arm64IdentOp("done")}}, emitBr, emitCondBr)
			return err
		}},
	}
	for _, tc := range errCases {
		if err := tc.run(); err == nil {
			t.Fatalf("%s unexpectedly succeeded", tc.name)
		}
	}

	cNoNext, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, sig, sigs)
	cNoNext.blocks = []arm64Block{{name: "solo"}}
	if _, _, err := cNoNext.lowerBranch(0, "BEQ", asm.Instr{Raw: "BEQ done", Args: []asm.Operand{arm64IdentOp("done")}}, arm64TestEmitBr(cNoNext), arm64TestEmitCondBr(cNoNext)); err == nil {
		t.Fatalf("BEQ without fallthrough unexpectedly succeeded")
	}
	if _, _, err := cNoNext.lowerBranch(0, "CBZ", asm.Instr{Raw: "CBZ R0, done", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cNoNext), arm64TestEmitCondBr(cNoNext)); err == nil {
		t.Fatalf("CBZ without fallthrough unexpectedly succeeded")
	}
	if _, _, err := cNoNext.lowerBranch(0, "TBZ", asm.Instr{Raw: "TBZ $1, R0, done", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cNoNext), arm64TestEmitCondBr(cNoNext)); err == nil {
		t.Fatalf("TBZ without fallthrough unexpectedly succeeded")
	}
	if _, _, err := cNoNext.lowerBranch(0, "CBZW", asm.Instr{Raw: "CBZW R0, done", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cNoNext), arm64TestEmitCondBr(cNoNext)); err == nil {
		t.Fatalf("CBZW without fallthrough unexpectedly succeeded")
	}

	cBadReg, _ := newARM64CtxWithFuncForTest(t, fn, sig, sigs)
	cBadReg.blocks = []arm64Block{{name: "entry"}, {name: "fall"}, {name: "done"}}
	delete(cBadReg.regSlot, asm.Reg("R0"))
	if _, _, err := cBadReg.lowerBranch(1, "BL", asm.Instr{Raw: "BL R0", Args: []asm.Operand{arm64RegOp("R0")}}, arm64TestEmitBr(cBadReg), arm64TestEmitCondBr(cBadReg)); err == nil {
		t.Fatalf("BL with missing reg unexpectedly succeeded")
	}
	if _, _, err := cBadReg.lowerBranch(1, "CBZ", asm.Instr{Raw: "CBZ R0, done", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cBadReg), arm64TestEmitCondBr(cBadReg)); err == nil {
		t.Fatalf("CBZ with missing reg unexpectedly succeeded")
	}
	if _, _, err := cBadReg.lowerBranch(1, "TBZ", asm.Instr{Raw: "TBZ $1, R0, done", Args: []asm.Operand{arm64ImmOp(1), arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cBadReg), arm64TestEmitCondBr(cBadReg)); err == nil {
		t.Fatalf("TBZ with missing reg unexpectedly succeeded")
	}
	if _, _, err := cBadReg.lowerBranch(1, "CBZW", asm.Instr{Raw: "CBZW R0, done", Args: []asm.Operand{arm64RegOp("R0"), arm64IdentOp("done")}}, arm64TestEmitBr(cBadReg), arm64TestEmitCondBr(cBadReg)); err == nil {
		t.Fatalf("CBZW with missing reg unexpectedly succeeded")
	}

	cBadMem, _ := newARM64CtxWithFuncForTest(t, fn, sig, sigs)
	cBadMem.blocks = []arm64Block{{name: "entry"}, {name: "fall"}, {name: "done"}}
	delete(cBadMem.regSlot, asm.Reg("R9"))
	if _, _, err := cBadMem.lowerBranch(1, "BL", asm.Instr{Raw: "BL 8(R9)", Args: []asm.Operand{arm64MemOp("R9", 8)}}, arm64TestEmitBr(cBadMem), arm64TestEmitCondBr(cBadMem)); err == nil {
		t.Fatalf("BL with bad mem unexpectedly succeeded")
	}
	if _, _, err := cBadMem.lowerBranch(1, "B", asm.Instr{Raw: "B 8(R9)", Args: []asm.Operand{arm64MemOp("R9", 8)}}, arm64TestEmitBr(cBadMem), arm64TestEmitCondBr(cBadMem)); err == nil {
		t.Fatalf("B with bad mem unexpectedly succeeded")
	}

	if err := c.callSym(arm64SymOp("ret8(SB)")); err != nil {
		t.Fatalf("callSym(ret8) error = %v", err)
	}
	if err := c.callSym(arm64SymOp("retptr(SB)")); err != nil {
		t.Fatalf("callSym(retptr) error = %v", err)
	}
	if err := c.callSym(arm64RegOp("R0")); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("broken")); err == nil {
		t.Fatalf("callSym(missing suffix) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("badarg(SB)")); err == nil {
		t.Fatalf("callSym(badarg) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("badret(SB)")); err == nil {
		t.Fatalf("callSym(badret) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("badagg(SB)")); err == nil {
		t.Fatalf("callSym(badagg) unexpectedly succeeded")
	}
	if err := c.callSym(arm64SymOp("badargreg(SB)")); err == nil {
		t.Fatalf("callSym(badargreg) unexpectedly succeeded")
	}

	cTailCast, bTailCast := newARM64CtxWithFuncForTest(t, fn, sig, sigs)
	if err := cTailCast.tailCallAndRet(arm64SymOp("casttail(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(casttail) error = %v", err)
	}
	for _, want := range []string{
		"trunc i64 %t3 to i32",
		"load i64, ptr %reg_R1",
		"load i64, ptr %reg_R2",
		"inttoptr i64 %t7 to ptr",
	} {
		if !strings.Contains(bTailCast.String(), want) {
			t.Fatalf("tailCallAndRet(casttail) missing %q:\n%s", want, bTailCast.String())
		}
	}

	cBadTailType, _ := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{
		Name: "example.badtailtypecaller",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.I64,
	}, sigs)
	if err := cBadTailType.tailCallAndRet(arm64SymOp("badtailtype(SB)")); err == nil {
		t.Fatalf("tailCallAndRet(badtailtype) unexpectedly succeeded")
	}

	cStructTail, _ := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.structcaller", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, sigs)
	if err := cStructTail.storeReg("R0", "21"); err != nil {
		t.Fatalf("storeReg(R0) error = %v", err)
	}
	if err := cStructTail.storeReg("R1", "22"); err != nil {
		t.Fatalf("storeReg(R1) error = %v", err)
	}
	if err := cStructTail.tailCallAndRet(arm64SymOp("structtail(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(structtail) error = %v", err)
	}

	cBadTailReg, _ := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.badtailregcaller", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, sigs)
	delete(cBadTailReg.regSlot, asm.Reg("BAD"))
	if err := cBadTailReg.tailCallAndRet(arm64SymOp("badtailreg(SB)")); err == nil {
		t.Fatalf("tailCallAndRet(badtailreg) unexpectedly succeeded")
	}

	cZeroRet, bZeroRet := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.zeroTail", Args: []asm.LLVMType{asm.I64}, Ret: asm.I64}, sigs)
	if err := cZeroRet.tailCallAndRet(arm64SymOp("voidsink2(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(voidsink2) error = %v", err)
	}
	if !strings.Contains(bZeroRet.String(), "ret i64 0") {
		t.Fatalf("tailCallAndRet(voidsink2) output = \n%s", bZeroRet.String())
	}

	cVoidCaller, bVoidCaller := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.voidCaller", Args: []asm.LLVMType{asm.I64}, Ret: asm.Void}, sigs)
	if err := cVoidCaller.tailCallAndRet(arm64SymOp("nonvoid(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(nonvoid) error = %v", err)
	}
	if !strings.Contains(bVoidCaller.String(), "ret void") {
		t.Fatalf("tailCallAndRet(nonvoid) output = \n%s", bVoidCaller.String())
	}

	cVoidTail, bVoidTail := newARM64CtxWithFuncForTest(t, fn, asm.FuncSig{Name: "example.voidTail", Args: []asm.LLVMType{asm.I64}, Ret: asm.Void}, sigs)
	if err := cVoidTail.tailCallAndRet(arm64SymOp("voidsink2(SB)")); err != nil {
		t.Fatalf("tailCallAndRet(void->void) error = %v", err)
	}
	if !strings.Contains(bVoidTail.String(), "ret void") {
		t.Fatalf("tailCallAndRet(void->void) output = \n%s", bVoidTail.String())
	}
}

func TestARM64CondCoverage(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.cond", Ret: asm.Void}, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "5"},
		{"R1", "6"},
		{"R2", "7"},
		{"R3", "8"},
		{"R4", "9"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}
	c.setFlagsSub("9", "3", "6")

	for _, ins := range []asm.Instr{
		{Op: "CSEL", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "CSEL EQ, R0, R1, R2"},
		{Op: "CSELW", Args: []asm.Operand{arm64IdentOp("NE"), arm64RegOp("R1"), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "CSELW NE, R1, R2, R3"},
		{Op: "CSET", Args: []asm.Operand{arm64IdentOp("GT"), arm64RegOp("R4")}, Raw: "CSET GT, R4"},
		{Op: "CNEG", Args: []asm.Operand{arm64IdentOp("LT"), arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "CNEG LT, R0, R1"},
		{Op: "CINC", Args: []asm.Operand{arm64IdentOp("HI"), arm64RegOp("R1"), arm64RegOp("R2")}, Raw: "CINC HI, R1, R2"},
	} {
		if ok, term, err := c.lowerCond(ins.Op, ins); !ok || term || err != nil {
			t.Fatalf("lowerCond(%s %q) = (%v, %v, %v)", ins.Op, ins.Raw, ok, term, err)
		}
	}

	badCases := []asm.Instr{
		{Op: "CSEL", Args: []asm.Operand{arm64RegOp("R0"), arm64RegOp("R1"), arm64RegOp("R2"), arm64RegOp("R3")}, Raw: "CSEL R0, R1, R2, R3"},
		{Op: "CSELW", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "CSELW EQ, R0, R1"},
		{Op: "CSET", Args: []asm.Operand{arm64IdentOp("EQ"), arm64ImmOp(1)}, Raw: "CSET EQ, $1"},
		{Op: "CNEG", Args: []asm.Operand{arm64IdentOp("EQ"), arm64ImmOp(1), arm64RegOp("R0")}, Raw: "CNEG EQ, $1, R0"},
		{Op: "CINC", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0"), arm64ImmOp(1)}, Raw: "CINC EQ, R0, $1"},
	}
	for _, ins := range badCases {
		if ok, term, err := c.lowerCond(ins.Op, ins); !ok || term || err == nil {
			t.Fatalf("lowerCond(%s bad) = (%v, %v, %v)", ins.Op, ok, term, err)
		}
	}

	cBadFlags, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.badflags", Ret: asm.Void}, nil)
	if ok, term, err := cBadFlags.lowerCond("CSET", asm.Instr{Op: "CSET", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0")}, Raw: "CSET EQ, R0"}); !ok || term || err == nil {
		t.Fatalf("lowerCond(CSET no flags) = (%v, %v, %v)", ok, term, err)
	}

	cBadReg, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.badreg", Ret: asm.Void}, nil)
	cBadReg.setFlagsSub("9", "3", "6")
	delete(cBadReg.regSlot, asm.Reg("R0"))
	if ok, term, err := cBadReg.lowerCond("CNEG", asm.Instr{Op: "CNEG", Args: []asm.Operand{arm64IdentOp("EQ"), arm64RegOp("R0"), arm64RegOp("R1")}, Raw: "CNEG EQ, R0, R1"}); !ok || term || err == nil {
		t.Fatalf("lowerCond(CNEG missing reg) = (%v, %v, %v)", ok, term, err)
	}

	out := b.String()
	for _, want := range []string{
		"select i1",
		"trunc i64",
		"zext i32",
		"select i1 %", // CSET/CSEL
		"sub i64 0",
		"add i64",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64EvalCoverage(t *testing.T) {
	sig := asm.FuncSig{
		Name: "example.eval64",
		Args: []asm.LLVMType{asm.Ptr, asm.I1, asm.I8, asm.I16, asm.I32, asm.I64, asm.LLVMType("double"), asm.LLVMType("float"), asm.LLVMType("{ ptr, i64 }")},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{
				{Offset: 0, Type: asm.Ptr, Index: 0},
				{Offset: 8, Type: asm.I1, Index: 1},
				{Offset: 16, Type: asm.I8, Index: 2},
				{Offset: 24, Type: asm.I16, Index: 3},
				{Offset: 32, Type: asm.I32, Index: 4},
				{Offset: 40, Type: asm.I64, Index: 5},
				{Offset: 48, Type: asm.LLVMType("double"), Index: 6},
				{Offset: 56, Type: asm.LLVMType("float"), Index: 7},
				{Offset: 64, Type: asm.I64, Index: 8, Field: 1},
			},
			Results: []asm.FrameSlot{{Offset: 80, Type: asm.I64, Index: 0}},
		},
	}
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, sig, nil)
	for _, tc := range []struct {
		r asm.Reg
		v string
	}{
		{"R0", "11"},
		{"R1", "12"},
		{"R2", "13"},
		{"R3", "14"},
		{"R4", "15"},
	} {
		if err := c.storeReg(tc.r, tc.v); err != nil {
			t.Fatalf("storeReg(%s) error = %v", tc.r, err)
		}
	}

	if got, base, inc, err := c.addrI64(asm.MemRef{Base: "R0", Index: "R1", Scale: 4, Off: 8}, true); err != nil || got == "" || base != "R0" || inc != 8 {
		t.Fatalf("addrI64() = (%q, %q, %d, %v)", got, base, inc, err)
	}
	if err := c.updatePostInc("R0", 8); err != nil {
		t.Fatalf("updatePostInc(8) error = %v", err)
	}
	if err := c.updatePostInc("R0", 0); err != nil {
		t.Fatalf("updatePostInc(0) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R2"}, 64, false); err != nil {
		t.Fatalf("loadMem(64) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R2", Off: 4}, 32, true); err != nil {
		t.Fatalf("loadMem(32) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R3"}, 16, false); err != nil {
		t.Fatalf("loadMem(16) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R4"}, 8, false); err != nil {
		t.Fatalf("loadMem(8) error = %v", err)
	}
	if _, err := c.loadMem(asm.MemRef{Base: "R4"}, 7, false); err == nil {
		t.Fatalf("loadMem(7) unexpectedly succeeded")
	}
	if err := c.storeMem(asm.MemRef{Base: "R2"}, 64, false, "21"); err != nil {
		t.Fatalf("storeMem(64) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R2", Off: 4}, 32, true, "22"); err != nil {
		t.Fatalf("storeMem(32) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R3"}, 16, false, "23"); err != nil {
		t.Fatalf("storeMem(16) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R4"}, 8, false, "24"); err != nil {
		t.Fatalf("storeMem(8) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R4"}, 1, false, "1"); err != nil {
		t.Fatalf("storeMem(1) error = %v", err)
	}
	if err := c.storeMem(asm.MemRef{Base: "R4"}, 7, false, "1"); err == nil {
		t.Fatalf("storeMem(7) unexpectedly succeeded")
	}

	ops := []asm.Operand{
		{Kind: asm.OpImm, Imm: 7},
		{Kind: asm.OpReg, Reg: "R0"},
		{Kind: asm.OpRegExtend, Reg: "R2", Ext: asm.ExtendUXTB},
		{Kind: asm.OpRegExtend, Reg: "R2", Ext: asm.ExtendUXTH},
		{Kind: asm.OpRegExtend, Reg: "R2", Ext: asm.ExtendUXTW},
		{Kind: asm.OpRegExtend, Reg: "R2", Ext: asm.ExtendUXTX},
		{Kind: asm.OpRegExtend, Reg: "R3", Ext: asm.ExtendSXTB},
		{Kind: asm.OpRegExtend, Reg: "R3", Ext: asm.ExtendSXTH},
		{Kind: asm.OpRegExtend, Reg: "R3", Ext: asm.ExtendSXTW},
		{Kind: asm.OpRegExtend, Reg: "R3", Ext: asm.ExtendSXTX},
		{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftLeft, ShiftAmount: 2},
		{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftRight, ShiftAmount: 1},
		{Kind: asm.OpFP, FPOffset: 0},
		{Kind: asm.OpFP, FPOffset: 8},
		{Kind: asm.OpFP, FPOffset: 16},
		{Kind: asm.OpFP, FPOffset: 24},
		{Kind: asm.OpFP, FPOffset: 32},
		{Kind: asm.OpFP, FPOffset: 40},
		{Kind: asm.OpFP, FPOffset: 48},
		{Kind: asm.OpFP, FPOffset: 56},
		{Kind: asm.OpFP, FPOffset: 64},
		{Kind: asm.OpFPAddr, FPOffset: 80},
		{Kind: asm.OpMem, Mem: asm.MemRef{Base: "R2", Off: 8}},
		{Kind: asm.OpSym, Sym: "$runtime·main+8(SB)"},
		{Kind: asm.OpSym, Sym: "8(R1)"},
		{Kind: asm.OpSym, Sym: "plain_symbol"},
		{Kind: asm.OpIdent, Ident: "NZCV"},
	}
	for _, op := range ops {
		if got, err := c.eval64(op, op.Kind == asm.OpMem); err != nil || got == "" {
			t.Fatalf("eval64(%s) = (%q, %v)", op.String(), got, err)
		}
	}
	if got, err := c.eval64(asm.Operand{Kind: asm.OpFPAddr, FPOffset: 88}, false); err != nil || got != "0" {
		t.Fatalf("eval64(missing fpaddr) = (%q, %v)", got, err)
	}
	if _, err := c.eval64(asm.Operand{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftRotate, ShiftReg: "R2"}, false); err == nil {
		t.Fatalf("eval64(register shift) unexpectedly succeeded")
	}
	if _, err := c.eval64(asm.Operand{Kind: asm.OpRegExtend, Reg: "R1", Ext: asm.ExtendOp("BAD")}, false); err == nil {
		t.Fatalf("eval64(bad extension) unexpectedly succeeded")
	}
	if got, err := c.eval64(asm.Operand{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftRotate, ShiftAmount: 1}, false); err != nil || got == "" {
		t.Fatalf("eval64(rotate) = (%q, %v)", got, err)
	}
	if _, err := c.eval64(asm.Operand{Kind: asm.OpRegShift, Reg: "R1", ShiftOp: asm.ShiftRotate, ShiftAmount: 64}, false); err == nil {
		t.Fatalf("eval64(out-of-range rotate) unexpectedly succeeded")
	}
	if _, err := c.eval64(asm.Operand{Kind: asm.OpLabel, Sym: "loop"}, false); err == nil {
		t.Fatalf("eval64(label) unexpectedly succeeded")
	}

	cBadSlot, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.badslot",
		Args: []asm.LLVMType{asm.LLVMType("{ ptr, { i64, i64 } }")},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{{Offset: 0, Type: asm.LLVMType("{ i64, i64 }"), Index: 0, Field: 1}},
		},
	}, nil)
	if _, err := cBadSlot.eval64(asm.Operand{Kind: asm.OpFP, FPOffset: 0}, false); err == nil {
		t.Fatalf("eval64(bad field type) unexpectedly succeeded")
	}

	cBadIndex, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.badidx",
		Args: []asm.LLVMType{asm.I64},
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Params: []asm.FrameSlot{{Offset: 0, Type: asm.I64, Index: 2}},
		},
	}, nil)
	if _, err := cBadIndex.eval64(asm.Operand{Kind: asm.OpFP, FPOffset: 0}, false); err == nil {
		t.Fatalf("eval64(bad fp index) unexpectedly succeeded")
	}
	if _, err := cBadIndex.eval64(asm.Operand{Kind: asm.OpMem, Mem: asm.MemRef{Base: "BAD"}}, false); err == nil {
		t.Fatalf("eval64(bad mem base) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"mul i64",
		"add i64",
		"load i64, ptr",
		"load i32, ptr",
		"load i16, ptr",
		"load i8, ptr",
		"store i64 21, ptr",
		"store i32",
		"store i16",
		"store i8",
		"store i1",
		"extractvalue { ptr, i64 } %arg8, 1",
		`getelementptr i8, ptr @"runtime.main", i64 8`,
		"ptrtoint ptr",
		"bitcast double %arg6 to i64",
		"bitcast float %arg7 to i32",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARM64FPResultCoverage(t *testing.T) {
	c, b := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.fpresults",
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{
				{Offset: 8, Type: asm.I64, Index: 0},
				{Offset: 16, Type: asm.I32, Index: 1},
				{Offset: 24, Type: asm.Ptr, Index: 2},
				{Offset: 32, Type: asm.LLVMType("double"), Index: 3},
				{Offset: 40, Type: asm.LLVMType("float"), Index: 4},
			},
		},
	}, nil)
	if _, ok := c.fpResultSlotByOffset(99); ok {
		t.Fatalf("fpResultSlotByOffset(99) unexpectedly found")
	}
	if err := c.storeFPResult64(8, "21"); err != nil {
		t.Fatalf("storeFPResult64(i64) error = %v", err)
	}
	if err := c.storeFPResult64(16, "22"); err != nil {
		t.Fatalf("storeFPResult64(i32) error = %v", err)
	}
	if err := c.storeFPResult64(24, "23"); err != nil {
		t.Fatalf("storeFPResult64(ptr) error = %v", err)
	}
	if err := c.storeFPResult64(32, "24"); err != nil {
		t.Fatalf("storeFPResult64(double) error = %v", err)
	}
	if err := c.storeFPResult64(40, "25"); err != nil {
		t.Fatalf("storeFPResult64(float) error = %v", err)
	}
	if _, err := c.loadFPResult(asm.FrameSlot{Index: 99, Type: asm.I64}); err == nil {
		t.Fatalf("loadFPResult(missing) unexpectedly succeeded")
	}
	for _, slot := range []asm.FrameSlot{
		{Index: 0, Type: asm.I64},
		{Index: 1, Type: asm.I32},
		{Index: 2, Type: asm.Ptr},
		{Index: 3, Type: asm.LLVMType("double")},
		{Index: 4, Type: asm.LLVMType("float")},
	} {
		if got, err := c.loadFPResult(slot); err != nil || got == "" {
			t.Fatalf("loadFPResult(%v) = (%q, %v)", slot, got, err)
		}
	}

	if err := c.storeReg("R0", "31"); err != nil {
		t.Fatalf("storeReg(R0) error = %v", err)
	}
	if err := c.storeReg("R1", "32"); err != nil {
		t.Fatalf("storeReg(R1) error = %v", err)
	}
	if err := c.storeReg("R2", "33"); err != nil {
		t.Fatalf("storeReg(R2) error = %v", err)
	}
	if err := c.storeReg("R3", "34"); err != nil {
		t.Fatalf("storeReg(R3) error = %v", err)
	}
	if got, err := c.loadRetSlotFallback(asm.FrameSlot{Index: 40, Type: asm.I16}); err != nil || got != "0" {
		t.Fatalf("loadRetSlotFallback(out-of-range) = (%q, %v)", got, err)
	}
	for _, slot := range []asm.FrameSlot{
		{Index: 0, Type: asm.I64},
		{Index: 1, Type: asm.Ptr},
		{Index: 2, Type: asm.LLVMType("double")},
		{Index: 3, Type: asm.LLVMType("float")},
		{Index: 1, Type: asm.I8},
	} {
		if got, err := c.loadRetSlotFallback(slot); err != nil || got == "" {
			t.Fatalf("loadRetSlotFallback(%v) = (%q, %v)", slot, got, err)
		}
	}
	if _, err := c.loadRetSlotFallback(asm.FrameSlot{Index: 0, Type: asm.LLVMType("{ i64, i64 }")}); err == nil {
		t.Fatalf("loadRetSlotFallback(aggregate) unexpectedly succeeded")
	}

	cMissingMeta, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{Name: "example.missingmeta", Ret: asm.Void}, nil)
	cMissingMeta.fpResAllocaOff[8] = "%fake"
	if err := cMissingMeta.storeFPResult64(8, "1"); err == nil {
		t.Fatalf("storeFPResult64(missing meta) unexpectedly succeeded")
	}
	cBadType, _ := newARM64CtxWithFuncForTest(t, asm.Func{}, asm.FuncSig{
		Name: "example.badtype",
		Ret:  asm.Void,
		Frame: asm.FrameLayout{
			Results: []asm.FrameSlot{{Offset: 8, Type: asm.LLVMType("{ i64, i64 }"), Index: 0}},
		},
	}, nil)
	if err := cBadType.storeFPResult64(8, "1"); err == nil {
		t.Fatalf("storeFPResult64(bad type) unexpectedly succeeded")
	}
	if err := cBadType.storeFPResult64(99, "1"); err == nil {
		t.Fatalf("storeFPResult64(bad off) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"store i64 21, ptr %fp_ret_0",
		"trunc i64 22 to i32",
		"inttoptr i64 23 to ptr",
		"bitcast i64 24 to double",
		"bitcast i32 %", // float path
		"load ptr, ptr %fp_ret_2",
		"bitcast i64 %", // fallback double
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
