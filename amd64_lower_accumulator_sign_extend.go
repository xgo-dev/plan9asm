package plan9asm

import "fmt"

// lowerAccumulatorSignExtend implements the complete Go 1.27 ynone family
// sharing opcodes 98/99: CBW/CWDE/CDQE extend into AX/EAX/RAX, while
// CWD/CDQ/CQO produce the sign half in DX/EDX/RDX. None of them modify flags.
func (c *amd64Ctx) lowerAccumulatorSignExtend(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, known, err := x86AccumulatorSignExtendProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	sourceType := amd64IntegerTypeForBits(int(spec.sourceBytes * 8))
	targetType := amd64IntegerTypeForBits(int(spec.destinationBytes * 8))
	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, sourceType)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	if spec.destination == AX {
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", result, sourceType, value, targetType)
	} else {
		bits, _ := amd64IntegerTypeBits(sourceType)
		fmt.Fprintf(c.b, "  %%%s = ashr %s %s, %d\n", result, sourceType, value, bits-1)
	}
	return true, false, c.storeRegSized(spec.destination, targetType, "%"+result)
}
