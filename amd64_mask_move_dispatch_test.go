package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestAMD64MaskMoveDispatchBindsCompleteFamily(t *testing.T) {
	// The internal lowerer takes the dispatched opcode separately. Older
	// helper callers intentionally leave Instr.Op unset; parsed instructions
	// retain their own opcode. Both must use the same complete _ykmovb grammar.
	forms := []struct {
		name string
		src  Operand
		dst  Operand
	}{
		{"mask_to_mask", Operand{Kind: OpReg, Reg: "K1"}, Operand{Kind: OpReg, Reg: "K2"}},
		{"mask_to_gp", Operand{Kind: OpReg, Reg: "K1"}, Operand{Kind: OpReg, Reg: AX}},
		{"gp_to_mask", Operand{Kind: OpReg, Reg: AX}, Operand{Kind: OpReg, Reg: "K2"}},
		{"mask_to_memory", Operand{Kind: OpReg, Reg: "K1"}, Operand{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}},
		{"memory_to_mask", Operand{Kind: OpMem, Mem: MemRef{Base: BX, Off: 8}}, Operand{Kind: OpReg, Reg: "K2"}},
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []Op{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
			for _, form := range forms {
				for _, instructionOp := range []Op{"", op, Op(strings.ToLower(string(op)))} {
					name := fmt.Sprintf("%s/%s/%s/op=%q", arch, op, form.name, instructionOp)
					t.Run(name, func(t *testing.T) {
						ins := Instr{Op: instructionOp, Args: []Operand{form.src, form.dst}}
						registered := ins
						registered.Op = op
						c, _ := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{registered}}, FuncSig{Ret: Void}, nil)
						c.goarch = arch
						if ok, terminated, err := c.lowerVec(op, ins); !ok || terminated || err != nil {
							t.Fatalf("lowerVec = (%v, %v, %v)", ok, terminated, err)
						}
						if ins.Op != instructionOp {
							t.Fatal("dispatch mutated its caller's instruction")
						}
					})
				}
			}
		}
	}
}

func TestAMD64MaskMoveDispatchRejectsContradictoryIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dispatch Op
		source   Op
	}{
		{"different_width", "KMOVB", "KMOVQ"},
		{"different_family", "KMOVB", "MOVQ"},
		{"unregistered_suffix", "KMOVB", "KMOVB.Z"},
		{"unknown_source", "KMOVB", "UNKNOWN"},
		{"unknown_dispatch", "UNKNOWN", "KMOVB"},
		{"both_unknown", "UNKNOWN", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ins := Instr{Op: tc.source, Args: []Operand{{Kind: OpReg, Reg: "K1"}, {Kind: OpReg, Reg: "K2"}}}
			c, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
			before := output.String()
			if err := c.lowerMaskMove(tc.dispatch, ins); err == nil {
				t.Fatal("accepted an unknown or contradictory mask-move opcode")
			}
			if output.String() != before {
				t.Fatal("invalid opcode emitted IR before rejection")
			}
		})
	}
}
