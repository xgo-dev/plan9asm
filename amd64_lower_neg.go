package plan9asm

import "fmt"

// Both complete unary families use Go's yscond(Ymb) grammar, including
// byte-register spellings of wide operations. Only NEG changes flags.
type x86UnaryYmbSpec struct {
	bits   int
	negate bool
}

var x86UnaryYmbSpecs = map[Op]x86UnaryYmbSpec{
	"NEGB": {bits: 8, negate: true},
	"NEGW": {bits: 16, negate: true},
	"NEGL": {bits: 32, negate: true},
	"NEGQ": {bits: 64, negate: true},
	"NOTB": {bits: 8},
	"NOTW": {bits: 16},
	"NOTL": {bits: 32},
	"NOTQ": {bits: 64},
}

func (c *amd64Ctx) lowerScalarUnaryYmb(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, recognized := x86UnaryYmbSpecs[op]
	if !recognized {
		return false, false, nil
	}
	bits := spec.bits
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", op, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one register/memory operand: %q", c.goarch, op, ins.Raw)
	}
	destination := ins.Args[0]
	if destination.Kind == OpReg {
		if !isGoYmbRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s register is outside Go 1.27's Ymb class: %q", c.goarch, op, ins.Raw)
		}
		destination.Reg = amd64YmbEffectiveRegister(destination.Reg, bits)
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s operand is outside Go 1.27's Ymb class: %q", c.goarch, op, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	value, store, err := c.loadIntDestination(destination, typ)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if !spec.negate {
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", result, typ, value)
		return true, false, store("%" + result)
	}
	fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", result, typ, value)
	if err := store("%" + result); err != nil {
		return true, false, err
	}
	// NEG has the same arithmetic flags as subtraction from zero: CF is set
	// exactly for nonzero inputs and OF is set only for the signed minimum.
	c.setScalarAddSubFlags(typ, false, "0", value, "%"+result)
	return true, false, nil
}
