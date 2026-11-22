package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

type x86DescriptorForm struct {
	mnemonic string
	effect   x86TypedByteOperand
}

const x86SystemAsmClobbers = "~{memory},~{dirflag},~{fpsr},~{flags}"

var x86DescriptorWriteWidths = x86OpcodeWidths{
	"SLDT": "WLQ",
	"SMSW": "WLQ",
	"STR":  "WLQ",
}

func x86DescriptorWriteOpcode(op string) (stem string, suffix byte, known bool) {
	if op == "" {
		return "", 0, false
	}
	last := len(op) - 1
	stem, suffix = op[:last], op[last]
	return stem, suffix, strings.ContainsRune(x86DescriptorWriteWidths[stem], rune(suffix))
}

func x86DescriptorTableOpcode(op string) bool {
	switch op {
	case "LGDT", "LIDT", "SGDT", "SIDT":
		return true
	default:
		return false
	}
}

func x86DescriptorProperties(opcode Op, ins Instr, arch string) (x86DescriptorForm, bool, error) {
	op, suffix, dotted := strings.Cut(strings.ToUpper(string(opcode)), ".")
	if op == "" {
		return x86DescriptorForm{}, false, nil
	}
	table := x86DescriptorTableOpcode(op)
	width, write := int64(2), false
	stem := op
	switch {
	case table:
		write = op[0] == 'S'
		width = 2 + x86ResultPointerWord(arch)
	case op == "LLDT", op == "LTR", op == "LMSW":
	default:
		var widthSuffix byte
		var known bool
		stem, widthSuffix, known = x86DescriptorWriteOpcode(op)
		if !known {
			return x86DescriptorForm{}, false, nil
		}
		write = true
		switch widthSuffix {
		case 'L':
			width = 4
		case 'Q':
			width = 8
		}
	}
	fail := func(reason string) (x86DescriptorForm, bool, error) {
		return x86DescriptorForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return fail("requires one descriptor operand")
	}
	if arch == "386" && width == 8 {
		return fail("is illegal in 32-bit mode")
	}
	operand := ins.Args[0]
	mnemonic := op
	if dotted {
		// Preserve the raw prefix independently of the mode's memory
		// width. In legacy mode it changes the base loaded by LGDT/LIDT.
		if !table || suffix != "W" || opcode != ins.Op || !x86RawDescriptorOrigin(ins, arch) {
			return fail("requires the original unsuffixed Go form or a decoded operand-size override")
		}
		mnemonic = "data16; " + op
	}
	if operand.Kind == OpReg {
		if table || !isX86YrlRegisterForArch(operand.Reg, arch) {
			return fail("has no matching GP register form")
		}
	} else {
		if !isAMD64MemoryOperand(operand) {
			return fail("requires a Go Ym memory operand")
		}
		if !table {
			// On memory operands the selector stays m16 for all W/L/Q
			// spellings. LLVM only accepts the unsuffixed memory form.
			mnemonic, width = stem, 2
		}
	}
	return x86DescriptorForm{
		mnemonic: strings.ToLower(mnemonic),
		effect:   x86TypedByteOperand{operand: operand, width: width, read: !write, write: write},
	}, true, nil
}

func (c *amd64Ctx) lowerDescriptorTable(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerSegmentQuery(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerFarPointer(op, ins); ok {
		return ok, terminated, err
	}
	form, known, err := x86DescriptorProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return true, false, c.emitDescriptor(form)
}

func (c *amd64Ctx) emitDescriptor(form x86DescriptorForm) error {
	effect := form.effect
	assembly := form.mnemonic + " $0"
	if effect.operand.Kind == OpReg {
		typ := amd64IntegerTypeForBits(int(effect.width * 8))
		if effect.write {
			result := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n", result, typ, assembly, "=r,"+x86SystemAsmClobbers)
			return c.storeRegSized(effect.operand.Reg, typ, "%"+result)
		}
		value, err := c.evalIntSized(effect.operand, typ)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n", assembly, "r,"+x86SystemAsmClobbers, typ, value)
		return nil
	}
	if !c.x86SystemFrameOperandFits(effect) {
		return fmt.Errorf("%w: descriptor operand exceeds its allocated FP slot", ErrProbeNeedsContext)
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(effect.operand)
	if err != nil {
		return err
	}
	constraints := "*m," + x86SystemAsmClobbers
	if effect.write {
		constraints = "=" + constraints
	}
	element := "i16"
	if effect.width != 2 {
		element = fmt.Sprintf("[%d x i8]", effect.width)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(%s) %s)\n",
		assembly, constraints, ptrType, element, ptr)
	return nil
}

func (c *amd64Ctx) x86SystemFrameOperandFits(effect x86TypedByteOperand) bool {
	operand := effect.operand
	if operand.Kind != OpFP || c.classicFrame != "" {
		return true
	}
	if parameter, known := c.fpParams[operand.FPOffset]; known {
		return effect.width <= x86FrameScalarBytes(parameter.Type, c.goarch)
	}
	_, result, known := c.fpResultAlloca(operand.FPOffset)
	return known && effect.width <= x86FrameScalarBytes(result, c.goarch)
}

func x86SystemOperandProperties(op Op, ins Instr, arch string) (x86TypedByteOperand, bool, error) {
	if form, known, err := x86DescriptorProperties(op, ins, arch); known {
		return form.effect, true, err
	}
	if op == ins.Op {
		op = x86GoMOVQSourceInstruction(ins).Op
	}
	form, known, err := x86MachineRegisterProperties(op, ins, arch)
	return form.effect, known, err
}

func x86LoweredSystemStep(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch, triple string) (bool, bool) {
	effect, known, err := x86SystemOperandProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86LoweredSystemOperandStep(ins, effect, state, owned, resultOffset, arch, triple), true
}

// The selected inline instruction retains its access and processor fault.
// Native addresses grant no local initialized bytes or pointer provenance.
func x86LoweredSystemOperandStep(ins Instr, effect x86TypedByteOperand, state *x86ResultState,
	owned []bool, resultOffset int64, arch, triple string) bool {
	if !x86ScalarFloatIntegerNativeTarget(arch, triple) ||
		!(x86ResultNamedPredicateInstruction(ins) || x86RawDescriptorOrigin(ins, arch)) {
		return false
	}
	operand := effect.operand
	if operand.Kind == OpReg && x86LogicalSourceFrameRegister(operand.Reg, arch) {
		return false // Physical stack changes need an entry/continuation contract.
	}
	if effect.read && x86ResultRead(operand, effect.width, state, owned, arch) {
		return true
	}
	if effect.write && x86ResultStore(operand, effect.width, state, owned, resultOffset, arch) {
		if index, mask, valid := x86ResultGP(operand.Reg, effect.width, arch); operand.Kind == OpReg && valid {
			state.canonicalGP[index] &^= mask
			if effect.width == 4 {
				state.canonicalGP[index] |= 0xf0
			}
		}
		return true
	}
	if _, symbol := x86StaticSBReadAddress(operand, arch); symbol {
		return true
	}
	return x86ResultIncomingPointerAddressIdentity(operand, state, arch) ||
		x86ResultNativeNumericAddress(operand, state, arch)
}

// Match descriptor table operands and decoded SLDT/SMSW/STR destinations.
// The origin does not supply an initialized address or frame.
func x86RawDescriptorOrigin(ins Instr, arch string) bool {
	origin := ins.x86SourceRaw
	if origin == nil || ins.Op != origin.op || len(ins.Args) != 1 ||
		origin.addressBits != 0 || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		ins.x86SegmentPrefix != 0 || ins.x86RawNearReturn != nil || ins.x86RIPLiteral {
		return false
	}
	base, _, _ := strings.Cut(string(ins.Op), ".")
	_, _, selectorStore := x86DescriptorWriteOpcode(string(ins.Op))
	if (!selectorStore && !x86DescriptorTableOpcode(base)) || !reflect.DeepEqual(origin.args, ins.Args) {
		return false
	}
	operand := ins.Args[0]
	return selectorStore && operand.Kind == OpReg ||
		x86RegisterAddressedNativeMemoryOperand(operand, arch) && operand.Mem.Segment == ""
}

func (c *amd64Ctx) x86DescriptorMemoryPointer(operand Operand) (ptr, ptrType string, err error) {
	switch operand.Kind {
	case OpMem:
		return c.ptrFromMem(operand.Mem)
	case OpSym:
		ptr, err := c.ptrFromSB(operand.Sym)
		return ptr, "ptr", err
	case OpFP:
		if c.classicFrame != "" {
			return c.classicFramePtr(operand.FPOffset), "ptr", nil
		}
		if ptr := c.fpParamAlloca[operand.FPOffset]; ptr != "" {
			return ptr, "ptr", nil
		}
		if ptr, _, ok := c.fpResultAlloca(operand.FPOffset); ok {
			return ptr, "ptr", nil
		}
		return "", "", fmt.Errorf("%s descriptor memory operand has no mutable FP slot at +%d(FP)", c.goarch, operand.FPOffset)
	default:
		return "", "", fmt.Errorf("%s descriptor instruction expected memory, got %s", c.goarch, operand.String())
	}
}
