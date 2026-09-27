package plan9asm

import "fmt"

type amd64ScalarExtensionMoveSpec struct {
	sourceBits      int
	destinationBits int
	signed          bool
	rejectedOn386   bool
}

// amd64ScalarExtensionMoveSpecs is the complete Go 1.27 x86 scalar
// sign/zero-extension family from the ymb_rl and yml_rl tables.
var amd64ScalarExtensionMoveSpecs = map[Op]amd64ScalarExtensionMoveSpec{
	"MOVBWSX": {sourceBits: 8, destinationBits: 16, signed: true},
	"MOVBWZX": {sourceBits: 8, destinationBits: 16},
	"MOVBLSX": {sourceBits: 8, destinationBits: 32, signed: true},
	"MOVBLZX": {sourceBits: 8, destinationBits: 32},
	"MOVBQSX": {sourceBits: 8, destinationBits: 64, signed: true, rejectedOn386: true},
	"MOVBQZX": {sourceBits: 8, destinationBits: 64, rejectedOn386: true},
	"MOVWLSX": {sourceBits: 16, destinationBits: 32, signed: true},
	"MOVWLZX": {sourceBits: 16, destinationBits: 32},
	"MOVWQSX": {sourceBits: 16, destinationBits: 64, signed: true, rejectedOn386: true},
	"MOVWQZX": {sourceBits: 16, destinationBits: 64, rejectedOn386: true},
	"MOVLQSX": {sourceBits: 32, destinationBits: 64, signed: true, rejectedOn386: true},
	// Go 1.27 accepts MOVLQZX in 386 mode because it is encoded as MOVL.
	"MOVLQZX": {sourceBits: 32, destinationBits: 64},
	"MOVSWW":  {sourceBits: 16, destinationBits: 16, signed: true},
	"MOVZWW":  {sourceBits: 16, destinationBits: 16},
}

func (c *amd64Ctx) lowerScalarExtensionMove(op Op, ins Instr) error {
	spec := amd64ScalarExtensionMoveSpecs[op]
	if c.goarch == "386" && spec.rejectedOn386 {
		return fmt.Errorf("386 %s is outside Go 1.27's scalar extension tables: %q", op, ins.Raw)
	}

	src, dst := ins.Args[0], ins.Args[1]
	if dst.Kind != OpReg || !isX86YrlRegisterForArch(dst.Reg, c.goarch) {
		return fmt.Errorf("amd64 %s expects a Yrl destination register: %q", op, ins.Raw)
	}
	if src.Kind == OpReg {
		valid := isX86YrlRegisterForArch(src.Reg, c.goarch)
		if spec.sourceBits == 8 {
			valid = isGoYmbRegisterForArch(src.Reg, c.goarch)
		}
		if !valid {
			return fmt.Errorf("amd64 %s source register is outside its Go 1.27 class: %q", op, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(src) {
		return fmt.Errorf("amd64 %s expects a register or memory source: %q", op, ins.Raw)
	}

	sourceType := amd64IntegerTypeForBits(spec.sourceBits)
	destinationType := amd64IntegerTypeForBits(spec.destinationBits)
	value, err := c.evalIntSized(src, sourceType)
	if err != nil {
		return err
	}
	if spec.sourceBits < spec.destinationBits {
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, sourceType, value, destinationType)
		value = "%" + extended
	}
	return c.storeRegSized(dst.Reg, destinationType, value)
}
