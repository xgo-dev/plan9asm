package plan9asm

import (
	"strings"
	"testing"
)

func TestEmitIRSourceCommentEdges(t *testing.T) {
	var b strings.Builder
	emitIRSourceComment(&b, "")
	if b.Len() != 0 {
		t.Fatalf("empty comment emitted %q", b.String())
	}
	emitIRSourceComment(&b, " \n\tMOVQ AX, BX\n\nRET\t\n")
	out := b.String()
	for _, want := range []string{
		"; s: MOVQ AX, BX",
		"; s: RET",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestParseIRModuleError(t *testing.T) {
	if _, err := parseIRModule("this is not valid llvm ir"); err == nil {
		t.Fatalf("parseIRModule(invalid) unexpectedly succeeded")
	}
}

func TestNeedCFGHelpers(t *testing.T) {
	if !funcNeedsAMD64CFG(Func{Instrs: []Instr{{Op: OpMOVQ, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: BX}}}}}) {
		t.Fatalf("funcNeedsAMD64CFG(mem mov) = false")
	}
	if !funcNeedsAMD64CFG(Func{Instrs: []Instr{{Op: "CRC32B"}}}) {
		t.Fatalf("funcNeedsAMD64CFG(crc32) = false")
	}
	if funcNeedsAMD64CFG(Func{Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}}, {Op: OpRET}}}) {
		t.Fatalf("funcNeedsAMD64CFG(straight-line) = true")
	}

	if !funcNeedsARMCFG(Func{Instrs: []Instr{{Op: "ADD.EQ"}}}) {
		t.Fatalf("funcNeedsARMCFG(cond exec) = false")
	}
	if !funcNeedsARMCFG(Func{Instrs: []Instr{{Op: "BL"}}}) {
		t.Fatalf("funcNeedsARMCFG(branch) = false")
	}
	if funcNeedsARMCFG(Func{Instrs: []Instr{{Op: OpTEXT}, {Op: "MOVW"}, {Op: "ADD"}, {Op: OpRET}}}) {
		t.Fatalf("funcNeedsARMCFG(linear subset) = true")
	}
}

func TestAMD64EvalI64Coverage(t *testing.T) {
	sig := FuncSig{
		Name: "example.eval",
		Args: []LLVMType{I64},
		Ret:  I64,
		Frame: FrameLayout{
			Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0}},
		},
	}
	c, b := newAMD64CtxWithFuncForTest(t, Func{}, sig, nil)
	if err := c.storeReg(AX, "17"); err != nil {
		t.Fatalf("storeReg(AX) error = %v", err)
	}
	if err := c.storeReg(BX, "128"); err != nil {
		t.Fatalf("storeReg(BX) error = %v", err)
	}

	if got, err := c.evalI64(Operand{Kind: OpImm, Imm: 7}); err != nil || got != "7" {
		t.Fatalf("evalI64(imm) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(Operand{Kind: OpReg, Reg: AX}); err != nil || got == "" {
		t.Fatalf("evalI64(reg) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(Operand{Kind: OpFP, FPOffset: 0}); err != nil || got == "" {
		t.Fatalf("evalI64(fp) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(Operand{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}); err != nil || got == "" {
		t.Fatalf("evalI64(mem) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(Operand{Kind: OpSym, Sym: "value<>(SB)"}); err != nil || got == "" {
		t.Fatalf("evalI64(sym) = (%q, %v)", got, err)
	}
	if got, err := c.evalI64(Operand{Kind: OpSym, Sym: "$value<>(SB)"}); err != nil || got == "" {
		t.Fatalf("evalI64(addr sym) = (%q, %v)", got, err)
	}
	if _, err := c.evalI64(Operand{Kind: OpSym, Sym: "bad sym"}); err == nil {
		t.Fatal("evalI64(unresolved bare sym) invented a value")
	}
	if _, err := c.evalI64(Operand{Kind: OpLabel, Sym: "loop"}); err == nil {
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
