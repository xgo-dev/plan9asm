package plan9asm

import "fmt"

func (c *amd64Ctx) lowerCrc32(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86CRC32Properties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.source.Kind == OpReg && (form.source.Reg == SP || form.source.Reg == BP) &&
		form.source.Reg != ins.Args[0].Reg {
		return true, false, fmt.Errorf("%w: Go CRC32 REX byte view needs its original physical SP/BP input", ErrProbeNeedsContext)
	}
	sourceType := amd64IntegerTypeForBits(form.bits)
	intrinsic := fmt.Sprintf("llvm.x86.sse42.crc32.32.%d", form.bits)
	resultType := I32
	if form.bits == 64 {
		resultType = I64
		intrinsic = "llvm.x86.sse42.crc32.64.64"
	}
	sourceValue, err := c.evalCRC32Source(ins, form, sourceType)
	if err != nil {
		return true, false, err
	}
	crcValue, err := c.evalIntSized(form.destination, I32)
	if err != nil {
		return true, false, err
	}
	if resultType == I64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", extended, crcValue)
		crcValue = "%" + extended // Unknown old high32 never enter the intrinsic.
	}
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s)\n", call, resultType, intrinsic, resultType, crcValue, sourceType, sourceValue)
	return true, false, c.storeRegSized(form.destination.Reg, resultType, "%"+call)
}

func (c *amd64Ctx) evalCRC32Source(ins Instr, form x86CRC32Form, typ LLVMType) (string, error) {
	if form.source.Kind == OpFP && x86ResultNamedPredicateInstruction(ins) {
		if value, handled, err := c.loadIntegerFPBytesMode(form.source.FPOffset, typ, true); handled || err != nil {
			return value, err
		}
	}
	if isAMD64MemoryOperand(form.source) && form.source.Kind != OpFP &&
		(x86OrdinaryNativeMemoryOperand(form.source, c.goarch) ||
			x86CallerMemoryCertified(ins, 0) || c.fixedLocalMemoryCertified(ins, 0)) {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return "", fmt.Errorf("%w: CRC32 needs its original native address size", ErrProbeNeedsContext)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		// Even a zero accumulator or dead result retains the complete native
		// source read. No backing, extent or alignment follows from continuing.
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
		return "%" + value, nil
	}
	return c.evalIntSized(form.source, typ)
}
