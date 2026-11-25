package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/arm"
	"github.com/xgo-dev/plan9asm/internal/arm64"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/x86"
)

func TestEmitIRSourceCommentEdges(t *testing.T) {
	var b strings.Builder
	asm.EmitIRSourceComment(&b, "")
	if b.Len() != 0 {
		t.Fatalf("empty comment emitted %q", b.String())
	}
	asm.EmitIRSourceComment(&b, " \n\tMOVQ AX, BX\n\nRET\t\n")
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
	if !x86.FuncNeedsCFG(Func{Instrs: []Instr{{Op: OpMOVQ, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: BX}}}}}) {
		t.Fatalf("x86.FuncNeedsCFG(mem mov) = false")
	}
	if !x86.FuncNeedsCFG(Func{Instrs: []Instr{{Op: "CRC32B"}}}) {
		t.Fatalf("x86.FuncNeedsCFG(crc32) = false")
	}
	if x86.FuncNeedsCFG(Func{Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}}, {Op: OpRET}}}) {
		t.Fatalf("x86.FuncNeedsCFG(straight-line) = true")
	}

	if !arm64.FuncNeedsCFG(Func{Instrs: []Instr{{Op: "MOVD.P"}}}) {
		t.Fatalf("arm64.FuncNeedsCFG(dot suffix) = false")
	}
	if !arm64.FuncNeedsCFG(Func{Instrs: []Instr{{Op: "B"}}}) {
		t.Fatalf("arm64.FuncNeedsCFG(branch) = false")
	}
	if arm64.FuncNeedsCFG(Func{Instrs: []Instr{{Op: OpTEXT}, {Op: OpMRS}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R0"}}}, {Op: OpRET}}}) {
		t.Fatalf("arm64.FuncNeedsCFG(linear subset) = true")
	}

	if !arm.FuncNeedsCFG(Func{Instrs: []Instr{{Op: "ADD.EQ"}}}) {
		t.Fatalf("arm.FuncNeedsCFG(cond exec) = false")
	}
	if !arm.FuncNeedsCFG(Func{Instrs: []Instr{{Op: "BL"}}}) {
		t.Fatalf("arm.FuncNeedsCFG(branch) = false")
	}
	if arm.FuncNeedsCFG(Func{Instrs: []Instr{{Op: OpTEXT}, {Op: "MOVW"}, {Op: "ADD"}, {Op: OpRET}}}) {
		t.Fatalf("arm.FuncNeedsCFG(linear subset) = true")
	}
}
