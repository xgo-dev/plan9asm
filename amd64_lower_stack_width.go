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

func (spec amd64StackWidthSpec) operandBits(operand Operand, arch string) int {
	if spec.segmentNativeWidth && x86SegmentRegisterOperand(operand) {
		return int(x86ResultPointerWord(arch)) * 8
	}
	return spec.bits
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

// This describes Go's complete value/FLAGS operand grammar, independently of
// a consumer's private-stack, segment-state or native-memory permissions.
func x86StackWidthProperties(ins Instr, arch string) (amd64StackWidthSpec, bool, error) {
	name := strings.ToUpper(string(ins.Op))
	base := strings.SplitN(name, ".", 2)[0]
	spec, known := amd64StackWidthSpecs[Op(base)]
	if !known {
		return spec, false, nil
	}
	fail := func() (amd64StackWidthSpec, bool, error) {
		return spec, true, fmt.Errorf("%s invalid %s stack form: %q", arch, base, ins.Raw)
	}
	if name != base {
		return fail()
	}
	flags := spec.mode == amd64StackPushFlags || spec.mode == amd64StackPopFlags
	if flags {
		if err := validateX86OrdinaryStackWidthMode(arch, base, spec.bits, ins); err != nil {
			return spec, true, err
		}
		if len(ins.Args) != 0 {
			return spec, true, fmt.Errorf("%s %s takes no operands: %q", arch, base, ins.Raw)
		}
		return spec, true, nil
	}
	if len(ins.Args) != 1 {
		role := "src"
		if spec.mode == amd64StackPopValue {
			role = "dst"
		}
		return spec, true, fmt.Errorf("%s %s expects %s: %q", arch, base, role, ins.Raw)
	}
	arg := ins.Args[0]
	if arg.Kind == OpImm && (arg.ImmRaw != "" || arg.ImmIsFloat || arg.Imm < -2147483648 || arg.Imm > 4294967295) {
		return fail()
	}
	if x86SegmentRegisterOperand(arg) {
		if !spec.segments.contains(arg.Reg) {
			return fail()
		}
		return spec, true, nil
	}
	if err := validateX86OrdinaryStackWidthMode(arch, base, spec.bits, ins); err != nil {
		return spec, true, err
	}
	if arg.Kind == OpReg {
		if !isX86YrlRegisterForArch(arg.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(arg) && !(spec.mode == amd64StackPushValue &&
		(arg.Kind == OpImm || x86AbsoluteRelocationSource(arg, arch, spec.bits))) {
		if spec.mode == amd64StackPopValue {
			return spec, true, fmt.Errorf("%s %s expects reg/mem dst in the Yrl class: %q", arch, base, ins.Raw)
		}
		return fail()
	}
	if arg.Kind == OpMem && !x86MemoryRegistersValidForArch(arg.Mem, arch) {
		return fail()
	}
	return spec, true, nil
}

func (c *amd64Ctx) lowerStackWidth(ins Instr, relativeAddress string) (ok bool, terminated bool, err error) {
	spec, known, err := x86StackWidthProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}

	switch spec.mode {
	case amd64StackPushFlags:
		value := c.packX86Flags()
		if spec.bits != 64 {
			value = c.truncI64(value, amd64StackLLVMType(spec.bits))
		}
		return true, false, c.pushStackWidth(spec.bits, value, relativeAddress)
	case amd64StackPopFlags:
		value, err := c.popStackWidth(spec.bits, relativeAddress)
		if err != nil {
			return true, false, err
		}
		if spec.bits != 64 {
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", extended, amd64StackLLVMType(spec.bits), value)
			value = "%" + extended
		}
		c.unpackX86Flags(value, spec.bits)
		return true, false, nil
	case amd64StackPushValue, amd64StackPopValue:
	default:
		panic("unknown x86 stack-width mode")
	}

	operand := ins.Args[0]
	if x86SegmentRegisterOperand(operand) {
		bits := spec.operandBits(operand, c.goarch)
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
			return true, false, c.pushStackWidth(bits, value, relativeAddress)
		}
		value, err := c.popStackWidth(bits, relativeAddress)
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
	if spec.mode == amd64StackPushValue {
		// PUSHQ encodes at most 32 immediate bits. Both immediate
		// encodings sign-extend their payload to the full stack word.
		if spec.bits == 64 && operand.Kind == OpImm {
			operand.Imm = int64(int32(operand.Imm))
		}
		value, err := c.loadStackValue(operand, spec.bits)
		if err != nil {
			return true, false, err
		}
		return true, false, c.pushStackWidth(spec.bits, value, relativeAddress)
	}

	value, err := c.popStackWidth(spec.bits, relativeAddress)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeStackWidth(operand, spec.bits, value, relativeAddress != "")
}

func validateX86OrdinaryStackWidthMode(arch, op string, bits int, ins Instr) error {
	if arch == "386" && bits == 64 {
		return fmt.Errorf("386 %s requires GOARCH=amd64: %q", op, ins.Raw)
	}
	if arch != "386" && bits == 32 {
		return fmt.Errorf("%s requires GOARCH=386: %q", op, ins.Raw)
	}
	return nil
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

func (c *amd64Ctx) pushStackWidth(bits int, value, address string) error {
	typ := amd64StackLLVMType(bits)
	if address == "" {
		if c.sourceStack != nil {
			return c.pushSourceStackValue(typ, int64(bits/8), value)
		}
		if c.goarch == "386" {
			switch bits {
			case 16:
				return c.pushI16(value)
			case 32:
				return c.pushI32(value)
			}
			return fmt.Errorf("386 cannot push %d-bit stack values", bits)
		}
		address = c.privateAMD64StackAddress(bits/8, true)
	}
	fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, value, address)
	return nil
}

func (c *amd64Ctx) popStackWidth(bits int, address string) (string, error) {
	typ := amd64StackLLVMType(bits)
	if address == "" {
		if c.sourceStack != nil {
			return c.popSourceStackValue(typ, int64(bits/8))
		}
		if c.goarch == "386" {
			switch bits {
			case 16:
				return c.popI16()
			case 32:
				return c.popI32()
			}
			return "", fmt.Errorf("386 cannot pop %d-bit stack values", bits)
		}
		address = c.privateAMD64StackAddress(bits/8, false)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, typ, address)
	return "%" + value, nil
}

func (c *amd64Ctx) storeStackWidth(destination Operand, bits int, value string, relative bool) error {
	typ := amd64StackLLVMType(bits)
	switch destination.Kind {
	case OpReg:
		return c.storeRegSized(destination.Reg, typ, value)
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		volatile := "volatile "
		if relative && destination.Mem.Base == SP {
			volatile = "" // The checked destination is in the private local object.
		}
		fmt.Fprintf(c.b, "  store %s%s %s, %s %s, align 1\n", volatile, typ, value, ptrType, ptr)
		return nil
	case OpSym:
		ptr, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store volatile %s %s, ptr %s, align 1\n", typ, value, ptr)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	default:
		return fmt.Errorf("%s stack destination is not writable", destination.String())
	}
}
