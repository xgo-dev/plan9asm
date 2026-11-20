package plan9asm

import "fmt"

// Only these normalized VEX family forms select an observable read. Legacy,
// registers and logical FP retain their existing evaluator and alias behavior.
// This is emission, never a source, address, extent or caller certificate.
func (c *amd64Ctx) loadAlternatingRoundFloat(operand Operand, width, bits int, observable bool) (string, error) {
	if observable && (operand.Kind == OpMem || operand.Kind == OpSym) {
		bytes, err := c.loadX86PackedShiftBytes(operand, width, true)
		if err != nil {
			return "", err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", result, width, bytes, amd64FMA3LLVMType(width*8/bits, bits))
		return "%" + result, nil
	}
	if width*8 == bits {
		return c.evalScalarFloatForInteger(operand, bits)
	}
	return c.loadHorizontalFloatingOperand(operand, width, bits)
}

func (c *amd64Ctx) loadRoundPackedBytes(form x86RoundForm) (string, error) {
	if form.spec.vector && (form.source.Kind == OpMem || form.source.Kind == OpSym) {
		return c.loadX86PackedShiftBytes(form.source, form.byteWidth, true)
	}
	return c.loadPackedCompareBytes(form.source, form.byteWidth)
}
