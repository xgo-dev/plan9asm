package plan9asm

import "fmt"

// lowerAccumulatorSignExtend implements the complete Go 1.27 ynone family
// sharing opcodes 98/99: CBW/CWDE/CDQE extend into AX/EAX/RAX, while
// CWD/CDQ/CQO produce the sign half in DX/EDX/RDX. None of them modify flags.
func (c *amd64Ctx) lowerAccumulatorSignExtend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	sourceType := LLVMType("")
	targetType := LLVMType("")
	destination := AX
	extendValue := true
	switch op {
	case "CBW":
		sourceType, targetType = I8, I16
	case "CWDE":
		sourceType, targetType = I16, I32
	case "CDQE":
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 CDQE is illegal in 32-bit mode: %q", ins.Raw)
		}
		sourceType, targetType = I32, I64
	case "CWD":
		sourceType, targetType, destination, extendValue = I16, I16, DX, false
	case "CDQ":
		sourceType, targetType, destination, extendValue = I32, I32, DX, false
	case "CQO":
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 CQO is illegal in 32-bit mode: %q", ins.Raw)
		}
		sourceType, targetType, destination, extendValue = I64, I64, DX, false
	default:
		return false, false, nil
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands in Go 1.27's ynone table: %q", c.goarch, op, ins.Raw)
	}
	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, sourceType)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if extendValue {
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", result, sourceType, value, targetType)
	} else {
		bits, _ := amd64IntegerTypeBits(sourceType)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", result, sourceType, value, bits-1)
	}
	return true, false, c.storeRegSized(destination, targetType, "%"+result)
}
