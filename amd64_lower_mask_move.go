package plan9asm

import "fmt"

// amd64MaskMoveSpecs is the complete Go 1.27 x86 mask-register move family.
// All four instructions share _ykmovb and its K->memory, K->GP,
// K-or-memory->K, and GP->K rows. Go accepts these rows in amd64 and 386 mode.
var amd64MaskMoveSpecs = map[Op]int{
	"KMOVB": 8,
	"KMOVW": 16,
	"KMOVD": 32,
	"KMOVQ": 64,
}

func (c *amd64Ctx) lowerMaskMove(op Op, ins Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("amd64 %s expects two operands from Go 1.27's _ykmovb table: %q", op, ins.Raw)
	}
	bits := amd64MaskMoveSpecs[op]
	src, dst := ins.Args[0], ins.Args[1]
	srcK := amd64IsKOperand(src)
	dstK := amd64IsKOperand(dst)
	srcGP := amd64IsYrlOperand(src, c.goarch)
	dstGP := amd64IsYrlOperand(dst, c.goarch)
	srcMem := isAMD64MemoryOperand(src)
	dstMem := isAMD64MemoryOperand(dst)

	valid := (srcK && (dstMem || dstGP || dstK)) || ((srcMem || srcGP) && dstK)
	if !valid {
		return fmt.Errorf("amd64 %s operands are outside Go 1.27's _ykmovb table: %q", op, ins.Raw)
	}

	value, err := c.loadMaskMoveValue(src, bits, srcK)
	if err != nil {
		return err
	}
	switch {
	case dstK:
		return c.storeK(dst.Reg, value)
	case dstGP:
		// The GP-destination encodings zero-extend B/W/D results. Store the
		// already-masked value as the complete modeled register value.
		base, _ := amd64FullRegBase(dst.Reg)
		return c.storeReg(base, value)
	case dstMem:
		return c.storeMaskMoveMemory(dst, bits, value)
	default:
		return fmt.Errorf("amd64 %s has unsupported destination: %q", op, ins.Raw)
	}
}

func amd64IsKOperand(operand Operand) bool {
	if operand.Kind != OpReg {
		return false
	}
	_, ok := amd64ParseKReg(operand.Reg)
	return ok
}

func amd64IsYrlOperand(operand Operand, goarch string) bool {
	return operand.Kind == OpReg && isX86YrlRegisterForArch(operand.Reg, goarch)
}

func (c *amd64Ctx) loadMaskMoveValue(src Operand, bits int, sourceIsK bool) (string, error) {
	if sourceIsK {
		value, err := c.loadK(src.Reg)
		if err != nil {
			return "", err
		}
		return c.maskMoveI64(value, bits), nil
	}

	typ := amd64IntegerTypeForBits(bits)
	value, err := c.evalIntSized(src, typ)
	if err != nil {
		return "", err
	}
	if bits == 64 {
		return value, nil
	}
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", extended, typ, value)
	return "%" + extended, nil
}

func (c *amd64Ctx) maskMoveI64(value string, bits int) string {
	if bits == 64 {
		return value
	}
	masked := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, value, amd64MaskWidthLiteral(bits))
	return "%" + masked
}

func (c *amd64Ctx) storeMaskMoveMemory(dst Operand, bits int, value string) error {
	typ := amd64IntegerTypeForBits(bits)
	stored := value
	if bits != 64 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", truncated, value, typ)
		stored = "%" + truncated
	}
	switch dst.Kind {
	case OpFP:
		return c.storeFPResult(dst.FPOffset, typ, stored)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, stored, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, stored, ptr)
		return nil
	default:
		return fmt.Errorf("amd64 mask move expected a memory destination, got %s", dst.String())
	}
}
