package plan9asm

import "fmt"

var arm64DoublingMultiplyLongEncodings = [...]struct {
	op                string
	register, indexed uint32
}{
	{op: "sqdmull", register: 0x0e20d000, indexed: 0x0f00b000},
	{op: "sqdmlal", register: 0x0e209000, indexed: 0x0f003000},
	{op: "sqdmlsl", register: 0x0e20b000, indexed: 0x0f007000},
}

type arm64RawDoublingMultiplyLong struct {
	op                  string
	highHalf            bool
	input, result       arm64VectorArrangement
	first, second, dest int
	lane                int // -1 selects the register form.
}

// A single pair of masks retains the scalar and vector layouts, preserving
// fixed bits outside Q, size, and the register/element fields. In scalar forms
// Q is fixed; in vector forms Q selects the upper source half.
func decodeARM64RawDoublingMultiplyLong(word uint32) (arm64RawDoublingMultiplyLong, bool) {
	const registerMask, indexedMask = 0xaf20fc00, 0xaf00f400
	scalar, q := word&(1<<28) != 0, word&(1<<30) != 0
	size := int(word >> 22 & 3)
	if size != 1 && size != 2 || scalar && !q {
		return arm64RawDoublingMultiplyLong{}, false
	}
	for _, encoding := range arm64DoublingMultiplyLongEncodings {
		indexed := word&indexedMask == encoding.indexed
		if !indexed && word&registerMask != encoding.register {
			continue
		}
		narrow := 8 << size
		lanes := 1
		if !scalar {
			lanes = 64 / narrow
		}
		form := arm64RawDoublingMultiplyLong{
			op: encoding.op, highHalf: q && !scalar,
			input:  arm64VectorArrangement{elementBits: narrow, lanes: lanes},
			result: arm64VectorArrangement{elementBits: 2 * narrow, lanes: lanes},
			first:  int(word >> 5 & 31), second: int(word >> 16 & 31), dest: int(word & 31),
			lane: -1,
		}
		if form.highHalf {
			form.input.lanes *= 2
		}
		if indexed {
			element := decodeARM64MultiplyIndexedElement(word, narrow)
			form.second, form.lane = element.register, element.lane
		}
		return form, true
	}
	return arm64RawDoublingMultiplyLong{}, false
}

func (c *arm64Ctx) lowerARM64RawDoublingMultiplyLong(form arm64RawDoublingMultiplyLong) error {
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 %s requires a native little-endian AArch64 FPSR target", ErrProbeNeedsContext, form.op)
	}
	bits := form.input.elementBits
	width := bits * form.input.lanes
	left, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.first)), width)
	if err != nil {
		return err
	}
	secondReg, secondWidth, constraint := arm64NativeSIMDReg(2, form.input), width, "w"
	if form.lane >= 0 {
		secondReg = fmt.Sprintf("$2.%c[%d]", arm64NativeSIMDBank(bits), form.lane)
		secondWidth = (form.lane + 1) * bits
		if bits == 16 {
			constraint = "x" // The indexed halfword register is V0–V15.
		}
	}
	right, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.second)), secondWidth)
	if err != nil {
		return err
	}

	op := form.op
	if form.highHalf {
		op += "2"
	}
	assembly := fmt.Sprintf("%s %s, %s, %s", op, arm64NativeSIMDReg(0, form.result),
		arm64NativeSIMDReg(1, form.input), secondReg)
	constraints := "=w,w," + constraint
	arguments := "<16 x i8> " + left + ", <16 x i8> " + right
	destination := Reg(fmt.Sprintf("V%d", form.dest))
	if form.op != "sqdmull" {
		old, err := c.loadVRegWidth(destination, form.result.elementBits*form.result.lanes)
		if err != nil {
			return err
		}
		constraints += ",0" // Destructive accumulate reads the old destination.
		arguments += ", <16 x i8> " + old
	}
	// Preserve the native instruction's product/accumulator saturation and
	// its sticky QC update, even when nothing uses the numerical result.
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s)\n",
		result, assembly, constraints+",~{memory}", arguments)
	return c.storeVReg(destination, "%"+result)
}
