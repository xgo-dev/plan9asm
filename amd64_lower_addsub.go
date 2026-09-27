package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarAddSub implements all operand rows in Go 1.27's yxorb (B) and
// yaddl (W/L/Q) tables for ADD and SUB.
func (c *amd64Ctx) lowerScalarAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	add, bits, recognized := amd64ScalarAddSubProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if err := validateAMD64ScalarAddSubInstruction(c.goarch, ins); err != nil {
		return true, false, err
	}
	source, destination := ins.Args[0], ins.Args[1]
	typ := amd64IntegerTypeForBits(bits)
	var sourceValue string
	if source.Kind == OpImm {
		sourceValue = amd64ScalarAddSubImmediate(source.Imm, bits)
	} else {
		sourceValue, err = c.evalIntSized(source, typ)
		if err != nil {
			return true, false, err
		}
	}
	destinationValue, store, err := c.loadIntDestination(destination, typ)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	llvmOp := "sub"
	if add {
		llvmOp = "add"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, llvmOp, typ, destinationValue, sourceValue)
	resultValue := "%" + result
	if err := store(resultValue); err != nil {
		return true, false, err
	}
	c.setScalarAddSubFlags(typ, add, destinationValue, sourceValue, resultValue)
	return true, false, nil
}

// validateAMD64ScalarAddSubInstruction is deliberately independent of a
// lowering context so the same Go-assembler table is enforced before either
// the direct/linear path or the CFG path is selected.
func validateAMD64ScalarAddSubInstruction(goarch string, ins Instr) error {
	rawOp := strings.ToUpper(string(ins.Op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	_, bits, recognized := amd64ScalarAddSubProperties(baseOp)
	if !recognized {
		return nil
	}
	if rawOp != baseOp {
		return fmt.Errorf("%s %s does not accept instruction suffixes: %q", goarch, baseOp, ins.Raw)
	}
	if goarch == "386" && bits == 64 {
		return fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return fmt.Errorf("%s %s expects source and destination: %q", goarch, baseOp, ins.Raw)
	}
	return validateAMD64ScalarAddSubOperands(goarch, baseOp, bits, ins.Args[0], ins.Args[1], ins)
}

func validateAMD64ScalarAddSubFunction(goarch string, fn Func) error {
	for _, ins := range fn.Instrs {
		if err := validateAMD64ScalarAddSubInstruction(goarch, ins); err != nil {
			return err
		}
	}
	return nil
}

func amd64ScalarAddSubProperties(op string) (add bool, bits int, ok bool) {
	switch op {
	case "ADDB":
		return true, 8, true
	case "ADDW":
		return true, 16, true
	case "ADDL":
		return true, 32, true
	case "ADDQ":
		return true, 64, true
	case "SUBB":
		return false, 8, true
	case "SUBW":
		return false, 16, true
	case "SUBL":
		return false, 32, true
	case "SUBQ":
		return false, 64, true
	default:
		return false, 0, false
	}
}

func validateAMD64ScalarAddSubOperands(goarch, baseOp string, bits int, source, destination Operand, ins Instr) error {
	registerAllowed := func(reg Reg) bool {
		if bits == 8 {
			// Although SP is in the wider general-register class, Go's
			// ADD/SUB byte tables do not accept it as a direct byte operand.
			return reg != SP && isGoYmbRegisterForArch(reg, goarch)
		}
		return isX86YrlRegisterForArch(reg, goarch)
	}
	destinationRegister := destination.Kind == OpReg && registerAllowed(destination.Reg)
	destinationMemory := isAMD64MemoryOperand(destination)
	if !destinationRegister && !destinationMemory {
		return fmt.Errorf("%s %s destination is outside Go 1.27's Ymb/Yml classes: %q", goarch, baseOp, ins.Raw)
	}
	switch source.Kind {
	case OpImm:
		if goarch != "386" && (source.Imm < -2147483648 || source.Imm > 4294967295) {
			return fmt.Errorf("amd64 %s immediate is outside Go 1.27's Yi32 class: %q", baseOp, ins.Raw)
		}
	case OpReg:
		if !registerAllowed(source.Reg) {
			return fmt.Errorf("%s %s source is outside Go 1.27's Yrb/Yrl classes: %q", goarch, baseOp, ins.Raw)
		}
	default:
		if !isAMD64MemoryOperand(source) || !destinationRegister {
			return fmt.Errorf("%s %s operands do not match Go 1.27's register/memory rows: %q", goarch, baseOp, ins.Raw)
		}
	}
	return nil
}

// The assembler emits only the low operand-width bits. Q-width immediates are
// encoded as imm32 and sign-extended by the CPU.
func amd64ScalarAddSubImmediate(immediate int64, bits int) string {
	return fmt.Sprintf("%d", amd64ScalarAddSubImmediateInt64(immediate, bits))
}

func amd64ScalarAddSubImmediateInt64(immediate int64, bits int) int64 {
	var normalized int64
	switch bits {
	case 8:
		normalized = int64(int8(uint8(immediate)))
	case 16:
		normalized = int64(int16(uint16(immediate)))
	case 32, 64:
		normalized = int64(int32(uint32(immediate)))
	}
	return normalized
}

func (c *amd64Ctx) setScalarAddSubFlags(typ LLVMType, add bool, destination, source, result string) {
	carry := c.newTmp()
	if add {
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", carry, typ, result, destination)
	} else {
		fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", carry, typ, destination, source)
	}
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)

	xorOperands := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorOperands, typ, destination, source)
	overflowInput := "%" + xorOperands
	if add {
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typ, overflowInput)
		overflowInput = "%" + inverted
	}
	xorResult := c.newTmp()
	overflowBits := c.newTmp()
	overflow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorResult, typ, destination, result)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", overflowBits, typ, overflowInput, xorResult)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", overflow, typ, overflowBits)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", overflow, c.flagsOFSlot)

	zero := c.newTmp()
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sign, typ, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	c.setParityFlagSized(typ, result)
}
