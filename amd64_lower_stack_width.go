package plan9asm

import (
	"fmt"
	"strings"
)

type amd64StackWidthMode uint8

const (
	amd64StackPushValue amd64StackWidthMode = iota
	amd64StackPopValue
	amd64StackPushFlags
	amd64StackPopFlags
)

type amd64StackWidthSpec struct {
	bits               int
	mode               amd64StackWidthMode
	segments           amd64StackSegmentSet
	segmentNativeWidth bool
}

type amd64StackSegmentSet uint8

const (
	amd64StackSegmentES amd64StackSegmentSet = 1 << iota
	amd64StackSegmentCS
	amd64StackSegmentSS
	amd64StackSegmentDS
	amd64StackSegmentFS
	amd64StackSegmentGS

	amd64StackPushSegments = amd64StackSegmentES | amd64StackSegmentCS |
		amd64StackSegmentSS | amd64StackSegmentDS | amd64StackSegmentFS |
		amd64StackSegmentGS
	amd64StackPopSegments  = amd64StackPushSegments &^ amd64StackSegmentCS
	amd64StackLongSegments = amd64StackSegmentFS | amd64StackSegmentGS
)

// amd64StackWidthSpecs models the value/flags, push/pop, width, and segment-set
// axes once for all Go x86 stack forms. Ordinary L spellings are 386-only and
// ordinary Q spellings are amd64-only. Go's separate ymovtab accepts its listed
// segment-register forms in both modes; L/Q use the target's native stack width.
var amd64StackWidthSpecs = map[Op]amd64StackWidthSpec{
	"PUSHW":  {bits: 16, mode: amd64StackPushValue, segments: amd64StackPushSegments},
	"POPW":   {bits: 16, mode: amd64StackPopValue, segments: amd64StackPopSegments},
	"PUSHL":  {bits: 32, mode: amd64StackPushValue, segments: amd64StackPushSegments, segmentNativeWidth: true},
	"POPL":   {bits: 32, mode: amd64StackPopValue, segments: amd64StackPopSegments, segmentNativeWidth: true},
	"PUSHQ":  {bits: 64, mode: amd64StackPushValue, segments: amd64StackLongSegments, segmentNativeWidth: true},
	"POPQ":   {bits: 64, mode: amd64StackPopValue, segments: amd64StackLongSegments, segmentNativeWidth: true},
	"PUSHFW": {bits: 16, mode: amd64StackPushFlags},
	"POPFW":  {bits: 16, mode: amd64StackPopFlags},
	"PUSHFL": {bits: 32, mode: amd64StackPushFlags},
	"POPFL":  {bits: 32, mode: amd64StackPopFlags},
	"PUSHFQ": {bits: 64, mode: amd64StackPushFlags},
	"POPFQ":  {bits: 64, mode: amd64StackPopFlags},
}

func (c *amd64Ctx) lowerStackWidth(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64StackWidthSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}

	switch spec.mode {
	case amd64StackPushFlags:
		if err := c.validateOrdinaryStackWidthMode(baseOp, spec.bits, ins); err != nil {
			return true, false, err
		}
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
		}
		value := c.packX86Flags()
		if spec.bits != 64 {
			value = c.truncI64(value, amd64StackLLVMType(spec.bits))
		}
		return true, false, c.pushStackWidth(spec.bits, value)
	case amd64StackPopFlags:
		if err := c.validateOrdinaryStackWidthMode(baseOp, spec.bits, ins); err != nil {
			return true, false, err
		}
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
		}
		value, err := c.popStackWidth(spec.bits)
		if err != nil {
			return true, false, err
		}
		if spec.bits != 64 {
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", extended, amd64StackLLVMType(spec.bits), value)
			value = "%" + extended
		}
		c.unpackX86Flags(value)
		return true, false, nil
	case amd64StackPushValue, amd64StackPopValue:
		if len(ins.Args) != 1 {
			role := "src"
			if spec.mode == amd64StackPopValue {
				role = "dst"
			}
			return true, false, fmt.Errorf("%s %s expects %s: %q", c.goarch, baseOp, role, ins.Raw)
		}
	default:
		panic("unknown x86 stack-width mode")
	}

	operand := ins.Args[0]
	segmentStack := x86SegmentRegisterOperand(operand)
	if segmentStack {
		if !spec.segments.contains(operand.Reg) {
			return true, false, fmt.Errorf("%s %s does not accept segment register %s in Go 1.27's ymovtab: %q", c.goarch, baseOp, operand.Reg, ins.Raw)
		}
		bits := spec.bits
		if spec.segmentNativeWidth {
			bits = c.x86NativeStackBits()
		}
		if spec.mode == amd64StackPushValue {
			selector := c.loadX86SegmentSelector(operand.Reg)
			value := selector
			switch bits {
			case 16:
				narrow := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", narrow, selector)
				value = "%" + narrow
			case 32:
			case 64:
				wide := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, selector)
				value = "%" + wide
			default:
				panic("invalid x86 segment stack width")
			}
			return true, false, c.pushStackWidth(bits, value)
		}
		value, err := c.popStackWidth(bits)
		if err != nil {
			return true, false, err
		}
		if bits != 16 {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc %s %s to i16\n", narrow, amd64StackLLVMType(bits), value)
			value = "%" + narrow
		}
		return true, false, c.storeX86SegmentSelector(operand.Reg, value)
	}
	if err := c.validateOrdinaryStackWidthMode(baseOp, spec.bits, ins); err != nil {
		return true, false, err
	}
	if spec.mode == amd64StackPushValue {
		if operand.Kind == OpReg {
			if !isX86YrlRegisterForArch(operand.Reg, c.goarch) {
				return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yrl class: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if operand.Kind != OpImm && !isAMD64MemoryOperand(operand) {
			return true, false, fmt.Errorf("%s %s expects Yrl/memory/immediate src: %q", c.goarch, baseOp, ins.Raw)
		}
		if operand.Kind == OpMem && !x86MemoryRegistersValidForArch(operand.Mem, c.goarch) {
			return true, false, fmt.Errorf("%s %s memory source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
		}
		value, err := c.evalIntSized(operand, amd64StackLLVMType(spec.bits))
		if err != nil {
			return true, false, err
		}
		return true, false, c.pushStackWidth(spec.bits, value)
	}

	if operand.Kind == OpReg {
		if !isX86YrlRegisterForArch(operand.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(operand) {
		return true, false, fmt.Errorf("%s %s expects reg/mem dst in the Yrl class: %q", c.goarch, baseOp, ins.Raw)
	}
	if operand.Kind == OpMem && !x86MemoryRegistersValidForArch(operand.Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s memory destination uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}
	value, err := c.popStackWidth(spec.bits)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeStackWidth(operand, spec.bits, value)
}

func (c *amd64Ctx) validateOrdinaryStackWidthMode(op string, bits int, ins Instr) error {
	if c.goarch == "386" && bits == 64 {
		return fmt.Errorf("386 %s requires GOARCH=amd64: %q", op, ins.Raw)
	}
	if c.goarch != "386" && bits == 32 {
		return fmt.Errorf("%s requires GOARCH=386: %q", op, ins.Raw)
	}
	return nil
}

func (c *amd64Ctx) x86NativeStackBits() int {
	if c.goarch == "386" {
		return 32
	}
	return 64
}

func (set amd64StackSegmentSet) contains(reg Reg) bool {
	var bit amd64StackSegmentSet
	switch reg {
	case ES:
		bit = amd64StackSegmentES
	case CS:
		bit = amd64StackSegmentCS
	case SS:
		bit = amd64StackSegmentSS
	case DS:
		bit = amd64StackSegmentDS
	case FS:
		bit = amd64StackSegmentFS
	case GS:
		bit = amd64StackSegmentGS
	default:
		return false
	}
	return set&bit != 0
}

func amd64StackLLVMType(bits int) LLVMType {
	switch bits {
	case 16:
		return I16
	case 32:
		return I32
	case 64:
		return I64
	default:
		panic("invalid x86 stack width")
	}
}

func (c *amd64Ctx) pushStackWidth(bits int, value string) error {
	if c.goarch == "386" {
		switch bits {
		case 16:
			return c.pushI16(value)
		case 32:
			return c.pushI32(value)
		}
		return fmt.Errorf("386 cannot push %d-bit stack values", bits)
	}
	if bits != 64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", extended, amd64StackLLVMType(bits), value)
		value = "%" + extended
	}
	c.pushI64(value)
	return nil
}

func (c *amd64Ctx) popStackWidth(bits int) (string, error) {
	if c.goarch == "386" {
		switch bits {
		case 16:
			return c.popI16()
		case 32:
			return c.popI32()
		}
		return "", fmt.Errorf("386 cannot pop %d-bit stack values", bits)
	}
	value := c.popI64()
	if bits == 64 {
		return value, nil
	}
	return c.truncI64(value, amd64StackLLVMType(bits)), nil
}

func (c *amd64Ctx) storeStackWidth(destination Operand, bits int, value string) error {
	typ := amd64StackLLVMType(bits)
	switch destination.Kind {
	case OpReg:
		return c.storeRegSized(destination.Reg, typ, value)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	default:
		return fmt.Errorf("%s stack destination is not writable", destination.String())
	}
}
