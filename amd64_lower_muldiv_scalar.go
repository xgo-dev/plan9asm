package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarMultiplyDivide implements the complete scalar x86 multiply and
// divide families described by Go 1.27's ydivb, ydivl, yimul, and yimul3
// tables. The one-operand forms use the architectural accumulator pairs;
// IMULW/L/Q also have the table's explicit two- and three-operand forms.
func (c *amd64Ctx) lowerScalarMultiplyDivide(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if known, terminated, err := c.lowerImplicitDivide(op, ins); known {
		return known, terminated, err
	}
	name := strings.ToUpper(string(op))
	stem, bits, threeOperandName, recognized := x86ScalarMultiplyDivideProperties(name)
	if !recognized {
		return false, false, nil
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", name, ins.Raw)
	}

	if threeOperandName {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("%s %s expects immediate, source, destination register: %q", c.goarch, name, ins.Raw)
		}
		form, _, err := x86ExplicitIMULProperties(Op(name), ins, c.goarch)
		if err != nil {
			return true, false, err
		}
		return true, false, c.emitX86ExplicitIMUL(bits, form.immediate, form.source, form.destination)
	}

	if stem == "IMUL" && bits != 8 && len(ins.Args) != 1 {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("%s %s expects one or two operands: %q", c.goarch, name, ins.Raw)
		}
		form, _, err := x86ExplicitIMULProperties(Op(name), ins, c.goarch)
		if err != nil {
			return true, false, err
		}
		return true, false, c.emitX86ExplicitIMUL(bits, Operand{}, form.source, form.destination)
	}

	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one GP-or-memory source: %q", c.goarch, name, ins.Raw)
	}
	if !isX86ScalarMultiplyDivideSource(ins.Args[0], bits, c.goarch) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's %s class: %q", c.goarch, name, x86ScalarMultiplyDivideSourceClass(bits), ins.Raw)
	}
	if (stem == "MUL" || stem == "IMUL") && x86ResultNamedPredicateInstruction(ins) {
		if _, _, err := x86ImplicitMultiplyProperties(op, ins, c.goarch); err != nil {
			return true, false, err
		}
	}

	switch stem {
	case "MUL":
		return true, false, c.emitX86ImplicitMultiply(bits, false, ins.Args[0], x86ResultNamedPredicateInstruction(ins))
	case "IMUL":
		return true, false, c.emitX86ImplicitMultiply(bits, true, ins.Args[0], x86ResultNamedPredicateInstruction(ins))
	default:
		panic("unreachable scalar multiply/divide stem")
	}
}

func x86ScalarMultiplyDivideProperties(op string) (stem string, bits int, threeOperandName bool, ok bool) {
	switch op {
	case "MULB":
		return "MUL", 8, false, true
	case "MULW":
		return "MUL", 16, false, true
	case "MULL":
		return "MUL", 32, false, true
	case "MULQ":
		return "MUL", 64, false, true
	case "IMULB":
		return "IMUL", 8, false, true
	case "IMULW":
		return "IMUL", 16, false, true
	case "IMULL":
		return "IMUL", 32, false, true
	case "IMULQ":
		return "IMUL", 64, false, true
	case "IMUL3W":
		return "IMUL", 16, true, true
	case "IMUL3L":
		return "IMUL", 32, true, true
	case "IMUL3Q":
		return "IMUL", 64, true, true
	case "DIVB":
		return "DIV", 8, false, true
	case "DIVW":
		return "DIV", 16, false, true
	case "DIVL":
		return "DIV", 32, false, true
	case "DIVQ":
		return "DIV", 64, false, true
	case "IDIVB":
		return "IDIV", 8, false, true
	case "IDIVW":
		return "IDIV", 16, false, true
	case "IDIVL":
		return "IDIV", 32, false, true
	case "IDIVQ":
		return "IDIV", 64, false, true
	default:
		return "", 0, false, false
	}
}

func x86ScalarMultiplyDivideSourceClass(bits int) string {
	if bits == 8 {
		return "Ymb"
	}
	return "Yml"
}

func isX86ScalarMultiplyDivideSource(operand Operand, bits int, goarch string) bool {
	if operand.Kind == OpReg {
		if bits == 8 {
			return isGoYmbRegisterForArch(operand.Reg, goarch)
		}
		return isX86YrlRegisterForArch(operand.Reg, goarch)
	}
	if operand.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
		return false
	}
	return isAMD64MemoryOperand(operand)
}

func validateX86ExplicitIMUL(goarch, op string, bits int, ins Instr, threeOperands bool) error {
	immediate := Operand{}
	source := ins.Args[0]
	destination := ins.Args[1]
	if threeOperands {
		immediate = ins.Args[0]
		source = ins.Args[1]
		destination = ins.Args[2]
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, goarch) {
		return fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", goarch, op, ins.Raw)
	}
	if threeOperands {
		if !isX86IMULImmediate(immediate, goarch) {
			return fmt.Errorf("%s %s immediate is outside Go 1.27's Yi8/Yi32 classes: %q", goarch, op, ins.Raw)
		}
		if !isX86ScalarMultiplyDivideSource(source, bits, goarch) {
			return fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", goarch, op, ins.Raw)
		}
		return nil
	}
	if source.Kind == OpImm {
		if !isX86IMULImmediate(source, goarch) {
			return fmt.Errorf("%s %s immediate is outside Go 1.27's Yi8/Yi32 classes: %q", goarch, op, ins.Raw)
		}
		return nil
	}
	if !isX86ScalarMultiplyDivideSource(source, bits, goarch) {
		return fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", goarch, op, ins.Raw)
	}
	return nil
}

func isX86IMULImmediate(operand Operand, goarch string) bool {
	if operand.Kind != OpImm {
		return false
	}
	// The 386 assembler classifies constants after truncating them to int32.
	// In amd64 mode Yi32 covers signed int32 through unsigned uint32.
	return goarch == "386" || (operand.Imm >= -2147483648 && operand.Imm <= 4294967295)
}

func (c *amd64Ctx) emitX86ImplicitMultiply(bits int, signed bool, source Operand, named bool) error {
	narrow := amd64IntegerTypeForBits(bits)
	wide := x86ScalarMultiplyDivideWideType(bits)
	var src string
	var err error
	handled := false
	if named && source.Kind == OpFP {
		src, handled, err = c.loadIntegerFPBytesMode(source.FPOffset, narrow, true)
	} else if named && x86RegisterAddressedNativeMemoryOperand(source, c.goarch) && source.Mem.Segment == "" {
		// Keep the exact source access even for a zero accumulator or dead
		// product. Address and AX inputs precede either implicit overwrite;
		// this emitter creates no caller, frame or reusable memory fact.
		src, err = c.evalSizedNativeGPSource(source, narrow, 0)
		handled = true
	}
	if !handled && err == nil {
		src, err = c.evalIntSized(source, narrow)
	}
	if err != nil {
		return err
	}
	acc, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, narrow)
	if err != nil {
		return err
	}
	lhs := c.extendX86MulDivValue(acc, narrow, wide, signed)
	rhs := c.extendX86MulDivValue(src, narrow, wide, signed)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, wide, lhs, rhs)

	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", low, wide, product, narrow)
	if bits == 8 {
		if err := c.storeRegSized(AX, I16, "%"+product); err != nil {
			return err
		}
	} else {
		shifted := c.newTmp()
		shift := "lshr"
		if signed {
			shift = "ashr"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s, %d\n", shifted, shift, wide, product, bits)
		high := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", high, wide, shifted, narrow)
		if err := c.storeRegSized(AX, narrow, "%"+low); err != nil {
			return err
		}
		if err := c.storeRegSized(DX, narrow, "%"+high); err != nil {
			return err
		}
	}
	c.setX86MultiplyOverflowFlags(narrow, wide, "%"+low, "%"+product, signed)
	return nil
}

func (c *amd64Ctx) emitX86ExplicitIMUL(bits int, immediate, source, destination Operand) error {
	typ := amd64IntegerTypeForBits(bits)
	wide := x86ScalarMultiplyDivideWideType(bits)
	right := ""
	var err error
	if source.Kind == OpImm {
		right = x86IMULImmediateValue(source.Imm, bits)
	} else {
		right, err = c.evalSizedNativeGPSource(source, typ, 0)
		if err != nil {
			return err
		}
	}
	left := ""
	if immediate.Kind == OpImm {
		left = x86IMULImmediateValue(immediate.Imm, bits)
	} else {
		left, err = c.evalIntSized(destination, typ)
		if err != nil {
			return err
		}
	}
	lhs := c.extendX86MulDivValue(left, typ, wide, true)
	rhs := c.extendX86MulDivValue(right, typ, wide, true)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", product, wide, lhs, rhs)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", low, wide, product, typ)
	if err := c.storeRegSized(destination.Reg, typ, "%"+low); err != nil {
		return err
	}
	c.setX86MultiplyOverflowFlags(typ, wide, "%"+low, "%"+product, true)
	return nil
}

func x86IMULImmediateValue(value int64, bits int) string {
	return fmt.Sprintf("%d", x86IMULEncodedImmediate(value, bits))
}

// The explicit IMUL emitter uses evalSizedNativeGPSource's exact volatile read.
// Continuing past it supplies only this instruction's numerical source bytes;
// the existing effect still owns old-destination, immediate and FLAGS roles.
func x86LoweredExplicitIMULNativeRead(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ExplicitIMULProperties(ins.Op, ins, arch)
	if !known || err != nil || form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
		!x86OrdinaryNativeMemoryOperand(form.source, arch) || ins.x86NumericalRead != nil {
		return false, false // Logical fields, static sources and actual source certificates keep their own consumers.
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	effect := x86ExplicitIMULByteEffect(form)
	if effect.dynamicMemory || state.flags&effect.flagsRead != effect.flagsRead {
		return false, true
	}
	for _, operand := range effect.operands {
		if !operand.read {
			continue
		}
		if operand.operand.Kind == OpReg {
			index, _, valid := x86ResultGP(operand.operand.Reg, operand.width, arch)
			if !valid || state.pointerGP[index] {
				return false, true
			}
		}
		if !x86ResultReadWithNativeGPContinuation(ins, operand.operand, operand.width, state, owned, arch) {
			return false, true
		}
	}
	for _, operand := range effect.operands {
		if operand.write && !x86ResultStore(operand.operand, operand.width, state, owned, resultOffset, arch) {
			return false, true
		}
	}
	state.flags = state.flags&^effect.flagsKilled | effect.flagsDefined
	return true, true
}

func x86IMULEncodedImmediate(value int64, bits int) int64 {
	switch bits {
	case 16:
		return int64(int16(value))
	case 32:
		return int64(int32(value))
	case 64:
		// x86-64 IMUL encodes this table's immediate as imm32 and sign
		// extends it to the qword operand width.
		return int64(int32(value))
	default:
		panic("unsupported explicit IMUL width")
	}
}

func (c *amd64Ctx) extendX86MulDivValue(value string, from, to LLVMType, signed bool) string {
	tmp := c.newTmp()
	op := "zext"
	if signed {
		op = "sext"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", tmp, op, from, value, to)
	return "%" + tmp
}

func x86ScalarMultiplyDivideWideType(bits int) LLVMType {
	if bits == 64 {
		return LLVMType("i128")
	}
	return amd64IntegerTypeForBits(bits * 2)
}

func (c *amd64Ctx) setX86MultiplyOverflowFlags(narrow, wide LLVMType, low, product string, signed bool) {
	var overflow string
	if signed {
		extended := c.extendX86MulDivValue(low, narrow, wide, true)
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, %s\n", cmp, wide, product, extended)
		overflow = "%" + cmp
	} else {
		extended := c.extendX86MulDivValue(low, narrow, wide, false)
		cmp := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %s, %s\n", cmp, wide, product, extended)
		overflow = "%" + cmp
	}
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", overflow, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", overflow, c.flagsOFSlot)
}
