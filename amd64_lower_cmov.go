package plan9asm

import "fmt"

// lowerConditionalMove implements the complete Go 1.27 yml_rl conditional
// move table: every x86 condition code at W/L/Q width, with a register or
// memory source and a GP-register destination.
func (c *amd64Ctx) lowerConditionalMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86ConditionalMoveProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	ty := amd64IntegerTypeForBits(form.bits)
	src, err := c.loadConditionalMoveSource(form, ins)
	if err != nil {
		return true, false, err
	}
	cur, err := c.evalIntSized(form.destination, ty)
	if err != nil {
		return true, false, err
	}
	condition, err := c.x86Condition(form.condition)
	if err != nil {
		return true, false, err
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", selected, condition, ty, src, ty, cur)
	// Select only the operand width, then apply the architectural writeback.
	// In particular a false L predicate still zeroes GP bits 63:32.
	return true, false, c.storeRegSized(form.destination.Reg, ty, "%"+selected)
}

func (c *amd64Ctx) loadConditionalMoveSource(form x86ConditionalMoveForm, ins Instr) (string, error) {
	source := form.source
	if source.Kind == OpReg {
		return c.evalIntSized(source, amd64IntegerTypeForBits(form.bits))
	}
	if source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, c.goarch) &&
		!x86CallerMemoryCertified(ins, 0) && !c.fixedLocalMemoryCertified(ins, 0) {
		return "", fmt.Errorf("%w: CMOV native stack source lacks its original storage certificate", ErrProbeNeedsContext)
	}
	if source.Kind == OpFP {
		// Only existing declared numerical ABI0 fields supply logical bytes.
		// Neither pointer fields, holes nor an unknown native frame are inputs.
		if err := c.validateX86PackedShiftFPSpan(source.FPOffset, form.bits/8); err != nil {
			return "", err
		}
		result := false
		for offset := source.FPOffset; offset < source.FPOffset+int64(form.bits/8); offset++ {
			slot, output, _ := c.fpVectorSlot(offset)
			if slot.Type != I8 && slot.Type != I16 && slot.Type != I32 && slot.Type != I64 && slot.Type != LLVMType("float") && slot.Type != LLVMType("double") {
				return "", fmt.Errorf("%w: CMOV FP byte is not declared numerical storage", ErrProbeNeedsContext)
			}
			result = result || output
		}
		if result {
			if err := c.scalarFPResultInitialized(); err != nil {
				return "", err
			}
		}
	}
	// The shared FP loader bitcasts floating slots before extracting bytes;
	// NaN payloads and signed zero are not floating-to-integer conversions.
	// Intel CMOVcc reads the complete memory source unconditionally, even for
	// a false predicate or dead result. Preserve the original width and fault.
	bytes, err := c.loadX86PackedShiftBytes(source, form.bits/8, true)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, form.bits/8, bytes, form.bits)
	if source.Kind != OpFP || c.classicFrame != "" {
		// LLVM22's x86 select expansion can sink even a volatile load into
		// one branch. An unconditional register use keeps the actual source
		// read before that expansion without emitting an instruction or
		// granting a new memory/FP permission. A false CMOV must still fault.
		fmt.Fprintf(c.b, "  call void asm sideeffect \"\", \"r\"(i%d %%%s)\n", form.bits, value)
	}
	return "%" + value, nil
}

func (c *amd64Ctx) x86Condition(code string) (string, error) {
	invert := func(value string) string {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", out, value)
		return "%" + out
	}
	combine := func(instruction, left, right string) string {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i1 %s, %s\n", out, instruction, left, right)
		return "%" + out
	}

	switch code {
	case "CC":
		return invert(c.loadFlag(c.flagsCFSlot)), nil
	case "CS":
		return c.loadFlag(c.flagsCFSlot), nil
	case "EQ":
		return c.loadFlag(c.flagsZSlot), nil
	case "GE", "GT", "LE", "LT":
		signedLess := combine("xor", c.loadFlag(c.flagsSltSlot), c.loadFlag(c.flagsOFSlot))
		switch code {
		case "LT":
			return signedLess, nil
		case "GE":
			return invert(signedLess), nil
		case "LE":
			return combine("or", c.loadFlag(c.flagsZSlot), signedLess), nil
		case "GT":
			return invert(combine("or", c.loadFlag(c.flagsZSlot), signedLess)), nil
		}
	case "HI":
		return combine("and", invert(c.loadFlag(c.flagsCFSlot)), invert(c.loadFlag(c.flagsZSlot))), nil
	case "LS":
		return combine("or", c.loadFlag(c.flagsCFSlot), c.loadFlag(c.flagsZSlot)), nil
	case "MI":
		return c.loadFlag(c.flagsSltSlot), nil
	case "NE":
		return invert(c.loadFlag(c.flagsZSlot)), nil
	case "OC":
		return invert(c.loadFlag(c.flagsOFSlot)), nil
	case "OS":
		return c.loadFlag(c.flagsOFSlot), nil
	case "PC":
		return invert(c.loadFlag(c.flagsPFSlot)), nil
	case "PL":
		return invert(c.loadFlag(c.flagsSltSlot)), nil
	case "PS":
		return c.loadFlag(c.flagsPFSlot), nil
	}
	return "", fmt.Errorf("unsupported x86 condition code %q", code)
}
