package plan9asm

import "fmt"

type amd64ImplicitMaskMoveSpec struct {
	byteWidth int
	vector    bool
}

// Go's frontend exposes the legacy SSE spelling both as MASKMOVOU and via
// the Intel-name alias MASKMOVDQU. MASKMOVQ is the corresponding MMX form;
// VMASKMOVDQU is the VEX spelling. All use the first operand as a byte mask,
// the second as data, and DI as the implicit memory destination.
var amd64ImplicitMaskMoveSpecs = map[Op]amd64ImplicitMaskMoveSpec{
	"MASKMOVQ":    {byteWidth: 8},
	"MASKMOVOU":   {byteWidth: 16},
	"MASKMOVDQU":  {byteWidth: 16},
	"VMASKMOVDQU": {byteWidth: 16, vector: true},
}

func (c *amd64Ctx) lowerImplicitMaskMove(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86ImplicitMaskMoveProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if spec.byteWidth == 8 || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
		!x86ResultNamedPredicateInstruction(ins) {
		return true, false, fmt.Errorf("%w: implicit mask store needs its original native source/target and MMX owner", ErrProbeNeedsContext)
	}
	mask, err := c.loadX(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	data, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	addressInteger, err := c.loadReg(DI)
	if err != nil {
		return true, false, err
	}
	address := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", address, addressInteger)
	mnemonic := "maskmovdqu"
	if spec.vector {
		mnemonic = "vmaskmovdqu"
	}
	// Preserve WC/non-temporal behavior and implementation-dependent
	// zero-mask address faults, not a removable masked store or a fabricated
	// unconditional read of the destination.
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<16 x i8> %s, <16 x i8> %s, ptr %%%s)\n",
		mnemonic+" $1, $0", "x,x,{di},~{memory}", data, mask, address)
	return true, false, nil
}
