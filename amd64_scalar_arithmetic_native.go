package plan9asm

import "fmt"

// The existing whole Go-table grammar supplies operand width, encoded byte
// aliases and carry roles. This query selects only its memory-to-register
// arithmetic/logical rows; it supplies no memory or entry capability.
func x86ScalarArithmeticNativeReadProperties(ins Instr, arch string) (x86LockScalarRMWForm, bool, error) {
	form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
	if !known {
		return form, false, nil
	}
	if err != nil {
		return form, true, err
	}
	switch form.spec.stem {
	case "ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR":
	default:
		return form, false, nil
	}
	if form.source.Kind != OpMem || form.source.Mem.Sym != "" ||
		form.destination.Kind != OpReg || !x86OrdinaryNativeMemoryOperand(form.source, arch) {
		return form, false, nil
	}
	return form, true, nil
}

func (c *amd64Ctx) evalScalarArithmeticSource(ins Instr, typ LLVMType) (string, Operand, error) {
	form, known, err := x86ScalarArithmeticNativeReadProperties(ins, c.goarch)
	if err != nil {
		return "", Operand{}, err
	}
	if !known {
		value, err := c.evalIntSized(ins.Args[0], typ)
		return value, ins.Args[1], err
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		form.destination.Reg != ins.Args[1].Reg && (form.destination.Reg == SP || form.destination.Reg == BP) {
		return "", Operand{}, fmt.Errorf("%w: scalar arithmetic needs its original native address/register contract", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
	if err != nil {
		return "", Operand{}, err
	}
	value := c.newTmp()
	// Preserve the fault and exact read even when all numerical results and
	// flags are discarded. Do not assert alignment, bounds or pointee validity.
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, typ, pointerType, pointer)
	return "%" + value, form.destination, nil
}

// Only the lowering paired with the exact volatile source load may consume
// its numerical continuation. The destination and incoming carry still need
// every source byte/flag. Public declaration and caller observers stay strict.
func x86LoweredScalarArithmeticNativeRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86ScalarArithmeticNativeReadProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	width := int64(form.spec.bits / 8)
	index, _, valid := x86ResultGP(form.destination.Reg, width, arch)
	if !valid || state.pointerGP[index] ||
		form.spec.carryInput && state.flags&x86ByteFlagCF == 0 ||
		!x86ResultRead(form.destination, width, state, owned, arch) ||
		!x86ResultReadWithNativeGPContinuation(ins, form.source, width, state, owned, arch) {
		return false, true
	}
	if !x86ResultStore(form.destination, width, state, owned, resultOffset, arch) {
		return false, true
	}
	state.flags = state.flags&^form.spec.flagsKilled | form.spec.flagsDefined
	return true, true
}
