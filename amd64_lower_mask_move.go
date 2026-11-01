package plan9asm

import (
	"fmt"
	"strings"
)

// amd64MaskMoveSpecs is the complete Go 1.27 x86 mask-register move family.
// All four instructions share _ykmovb and its K->memory, K->GP,
// K-or-memory->K, and GP->K rows. Go accepts these rows in amd64 and 386 mode.
var amd64MaskMoveSpecs = map[Op]int{
	"KMOVB": 8,
	"KMOVW": 16,
	"KMOVD": 32,
	"KMOVQ": 64,
}

type x86MaskMoveOperandKind uint8

const (
	x86MaskMoveK x86MaskMoveOperandKind = iota
	x86MaskMoveGP
	x86MaskMoveMemory
)

type x86MaskMoveForm struct {
	bits                int
	source, destination x86MaskMoveOperandKind
}

// Only a GP operand binds the mode-effective word width: VEX.W is ignored
// for GP transfers in mode32. K/K and K/memory keep the original native width.
func x86MaskMoveProperties(op Op, ins Instr, arch string) (x86MaskMoveForm, bool, error) {
	bits, known := amd64MaskMoveSpecs[op]
	form := x86MaskMoveForm{bits: bits}
	if !known {
		return form, false, nil
	}
	fail := func() (x86MaskMoveForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands are outside Go's _ykmovb table: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 {
		return fail()
	}
	kind := func(operand Operand) (x86MaskMoveOperandKind, bool) {
		switch {
		case amd64IsKOperand(operand):
			return x86MaskMoveK, true
		case amd64IsYrlOperand(operand, arch):
			return x86MaskMoveGP, true
		case isAMD64MemoryOperand(operand):
			return x86MaskMoveMemory, true
		}
		return 0, false
	}
	var sourceOK, destinationOK bool
	form.source, sourceOK = kind(ins.Args[0])
	form.destination, destinationOK = kind(ins.Args[1])
	if !sourceOK || !destinationOK || form.source != x86MaskMoveK && form.destination != x86MaskMoveK {
		return fail()
	}
	if form.source == x86MaskMoveGP || form.destination == x86MaskMoveGP {
		if word := int(x86ResultPointerWord(arch) * 8); form.bits > word {
			form.bits = word
		}
	}
	return form, true, nil
}

func (c *amd64Ctx) lowerMaskMove(op Op, ins Instr) error {
	if ins.Op != "" && Op(strings.ToUpper(string(ins.Op))) != op {
		return fmt.Errorf("amd64 mask-move dispatch %q disagrees with instruction %q", op, ins.Op)
	}
	// The internal dispatcher owns the opcode argument, including for helper
	// callers without Instr.Op. Bind a local copy before the shared validator;
	// source/caller proofs still require their original complete instruction.
	ins.Op = op
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86MaskMoveProperties(op, ins, arch)
	if !known {
		return fmt.Errorf("amd64 unknown mask-move opcode %q", op)
	}
	if err != nil {
		return err
	}
	src, dst := ins.Args[0], ins.Args[1]
	value, err := c.loadMaskMoveValue(src, form.bits, form.source == x86MaskMoveK)
	if err != nil {
		return err
	}
	switch form.destination {
	case x86MaskMoveK:
		return c.storeK(dst.Reg, value)
	case x86MaskMoveGP:
		// The GP-destination encodings zero-extend B/W/D results. Store the
		// already-masked value as the complete modeled register value.
		base, _ := amd64FullRegBase(dst.Reg)
		return c.storeReg(base, value)
	case x86MaskMoveMemory:
		return c.storeMaskMoveMemory(dst, form.bits, value)
	default:
		return fmt.Errorf("amd64 %s has unsupported destination: %q", op, ins.Raw)
	}
}

func amd64MaskMoveOperandsValid(ins Instr, goarch string) bool {
	_, known, err := x86MaskMoveProperties(ins.Op, ins, goarch)
	return known && err == nil
}

func x86TypedMaskMoveByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86MaskMoveProperties(op, ins, arch)
	if !known {
		return x86TypedByteEffect{}, false, nil
	}
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	width := int64(form.bits / 8)
	first, last := ins.Args[0], ins.Args[1]
	writeWidth := width
	if form.destination == x86MaskMoveGP && writeWidth < x86ResultPointerWord(arch) {
		writeWidth = x86ResultPointerWord(arch) // GP B/W/D writes zero-extend; memory stays exact-width.
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: first, width: width, read: true},
		{index: 1, operand: last, width: writeWidth, write: true},
	}}, true, nil
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
	var value string
	var err error
	if src.Kind == OpFP && c.fpScalarSource.x86SourceStack == nil && c.fpScalarSource.x86FixedLocal == nil {
		// A mask memory width is not its first logical field's type. Gather
		// precisely those bytes, including interior and cross-field reads.
		value, err = c.loadScalarLaneFPBits(src.FPOffset, bits)
	} else if src.Kind == OpMem || src.Kind == OpSym {
		pointer, pointerType, _, pointerErr := c.packedVectorMemoryPointer(src)
		if pointerErr != nil {
			return "", pointerErr
		}
		temporary := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", temporary, typ, pointerType, pointer)
		value = "%" + temporary
	} else {
		value, err = c.evalIntSized(src, typ)
	}
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
		if c.fpScalarSource.x86SourceStack == nil && c.fpScalarSource.x86FixedLocal == nil {
			// Scatter only the native write width; a B/W/D store must retain
			// the initialized remainder of a larger logical result field.
			return c.storeScalarLaneFPBits(dst.FPOffset, bits, stored)
		}
		return c.storeFPResult(dst.FPOffset, typ, stored)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, stored, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, ptr %s, align 1\n", typ, stored, ptr)
		return nil
	default:
		return fmt.Errorf("amd64 mask move expected a memory destination, got %s", dst.String())
	}
}
