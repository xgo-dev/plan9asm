package plan9asm

import "fmt"

type amd64BMI2ShiftSpec struct {
	bits   int
	prefix int
	kind   string
}

var amd64BMI2ShiftSpecs = map[string]amd64BMI2ShiftSpec{
	"SARXL": {bits: 32, prefix: 2, kind: "ashr"},
	"SARXQ": {bits: 64, prefix: 2, kind: "ashr"},
	"SHLXL": {bits: 32, prefix: 1, kind: "shl"},
	"SHLXQ": {bits: 64, prefix: 1, kind: "shl"},
	"SHRXL": {bits: 32, prefix: 3, kind: "lshr"},
	"SHRXQ": {bits: 64, prefix: 3, kind: "lshr"},
}

// lowerBMI2VariableShift implements the six SARX/SHLX/SHRX L/Q opcodes. Go
// 1.27 gives all of them the single _ybextrl row: Yrl count, Yml source, Yrl
// destination. Unlike legacy shifts, the count must be a register and flags
// are not modified.
func (c *amd64Ctx) lowerBMI2VariableShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, supported := amd64BMI2ShiftSpecs[string(op)]
	if !supported {
		return false, false, nil
	}
	bits := spec.bits
	if c.goarch == "386" {
		// Go accepts Q spellings, but VEX.W is ignored outside 64-bit mode.
		// Both the memory access and the count mask must remain 32-bit.
		bits = 32
	}

	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects count register, register/memory source, and destination register: %q", c.goarch, op, ins.Raw)
	}
	count, source, destination := ins.Args[0], ins.Args[1], ins.Args[2]
	if count.Kind != OpReg || !isX86YrlRegisterForArch(count.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s count is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
	}
	if source.Kind == OpReg {
		if !isX86YrlRegisterForArch(source.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	countValue, err := c.evalIntSized(count, typ)
	if err != nil {
		return true, false, err
	}
	sourceValue, err := c.evalIntSized(source, typ)
	if err != nil {
		return true, false, err
	}
	maskedCount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", maskedCount, typ, countValue, bits-1)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", result, spec.kind, typ, sourceValue, maskedCount)
	if err := c.storeRegSized(destination.Reg, typ, "%"+result); err != nil {
		return true, false, err
	}
	return true, false, nil
}
