package plan9asm

import "fmt"

type amd64BMI2ShiftSpec struct {
	bits      int
	prefix    int
	kind      string
	immediate bool
}

var amd64BMI2ShiftSpecs = map[Op]amd64BMI2ShiftSpec{
	"SARXL": {bits: 32, prefix: 2, kind: "ashr"},
	"SARXQ": {bits: 64, prefix: 2, kind: "ashr"},
	"SHLXL": {bits: 32, prefix: 1, kind: "shl"},
	"SHLXQ": {bits: 64, prefix: 1, kind: "shl"},
	"SHRXL": {bits: 32, prefix: 3, kind: "lshr"},
	"SHRXQ": {bits: 64, prefix: 3, kind: "lshr"},
	"RORXL": {bits: 32, prefix: 3, kind: "rotate", immediate: true},
	"RORXQ": {bits: 64, prefix: 3, kind: "rotate", immediate: true},
}

// All eight L/Q shifts and rotates consume the shared complete _ybextrl or
// _yrorxl grammar, exact source width and count mask. None changes FLAGS.
func (c *amd64Ctx) lowerBMI2ShiftRotate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, supported := amd64BMI2ShiftSpecs[op]
	if !supported {
		return false, false, nil
	}
	form, _, err := x86ScalarShiftProperties(op, ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(form.bits)
	countValue, err := c.evalIntSized(form.count, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, _, err := c.loadScalarShiftOperand(ins, 1, typ)
	if err != nil {
		return true, false, err
	}
	maskedCount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", maskedCount, typ, countValue, form.bits-1)
	result := c.newTmp()
	if spec.immediate {
		// Both shifts stay in range at count zero; LLVM must never see poison.
		negative, reverse := c.newTmp(), c.newTmp()
		low, high := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", negative, typ, maskedCount)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", reverse, typ, negative, form.bits-1)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", low, typ, sourceValue, maskedCount)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", high, typ, sourceValue, reverse)
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", result, typ, low, high)
	} else {
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, spec.kind, typ, sourceValue, maskedCount)
	}
	if err := c.storeRegSized(form.destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	return true, false, nil
}
