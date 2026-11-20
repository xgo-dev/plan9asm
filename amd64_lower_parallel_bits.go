package plan9asm

import "fmt"

// Both BMI2 families share the complete three-word grammar with ANDN.
// Their operation and preserved FLAGS remain separate.
func (c *amd64Ctx) lowerParallelBitDepositExtract(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86TernaryGPProperties(op, ins, c.goarch)
	if !known || form.spec.operation == x86TernaryANDN {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	bits := form.spec.bits
	typ := amd64IntegerTypeForBits(bits)
	mask, err := c.evalSizedNativeGPSource(form.first, typ, ins.x86AddressBits)
	if err != nil {
		return true, false, err
	}
	source, err := c.evalIntSized(form.second, typ)
	if err != nil {
		return true, false, err
	}
	result := c.emitParallelBitOperation(form.spec.operation == x86TernaryPDEP, bits, mask, source)
	return true, false, c.storeRegSized(form.destination.Reg, typ, result)
}

// emitParallelBitOperation emits target-independent LLVM so translated code
// retains PDEP/PEXT semantics even when the LLVM execution host lacks BMI2.
// cursor is at most bit before each iteration, so every variable shift stays
// strictly below the integer width and cannot produce LLVM poison.
func (c *amd64Ctx) emitParallelBitOperation(deposit bool, bits int, mask, source string) string {
	typ := fmt.Sprintf("i%d", bits)
	result := "0"
	cursor := "0"
	for bit := 0; bit < bits; bit++ {
		shiftedMask := c.newTmp()
		maskBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shiftedMask, typ, mask, bit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", maskBit, typ, shiftedMask)

		sourceShift := cursor
		destinationShift := fmt.Sprintf("%d", bit)
		if !deposit {
			sourceShift = fmt.Sprintf("%d", bit)
			destinationShift = cursor
		}
		shiftedSource := c.newTmp()
		sourceBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shiftedSource, typ, source, sourceShift)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", sourceBit, typ, shiftedSource)
		placed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", placed, typ, sourceBit, destinationShift)
		enabledMask := c.newTmp()
		enabled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", enabledMask, typ, maskBit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", enabled, typ, placed, enabledMask)
		nextResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", nextResult, typ, result, enabled)
		result = "%" + nextResult
		nextCursor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", nextCursor, typ, cursor, maskBit)
		cursor = "%" + nextCursor
	}
	return result
}
