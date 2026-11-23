package plan9asm

import (
	"fmt"
	"math/bits"
)

// Native SIMD constraints carry a whole V register. Validated instruction
// forms select the scalar subregister or the active vector arrangement.
func arm64NativeSIMDReg(index int, arrangement arm64VectorArrangement) string {
	bank := arm64NativeSIMDBank(arrangement.elementBits)
	if arrangement.lanes == 1 {
		return fmt.Sprintf("${%d:%c}", index, bank)
	}
	return fmt.Sprintf("$%d.%d%c", index, arrangement.lanes, bank)
}

func arm64NativeSIMDBank(elementBits int) byte {
	return "bhsd"[bits.TrailingZeros(uint(elementBits))-3]
}

type arm64NarrowOperands struct {
	bits                int // Narrow element width.
	source, destination int
	scalar, highHalf    bool
}

func (f arm64NarrowOperands) arrangements() (source, destination arm64VectorArrangement) {
	lanes := 1
	if !f.scalar {
		lanes = 64 / f.bits
	}
	source = arm64VectorArrangement{2 * f.bits, lanes}
	destination = arm64VectorArrangement{f.bits, lanes}
	if f.highHalf {
		destination.lanes *= 2
	}
	return source, destination
}

func (c *arm64Ctx) lowerARM64NativeNarrow(form arm64NarrowOperands, mnemonic string, shift int, mergeScalar bool) error {
	sourceView, destinationView := form.arrangements()
	source, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.source)), sourceView.lanes*sourceView.elementBits)
	if err != nil {
		return err
	}

	destination := Reg(fmt.Sprintf("V%d", form.destination))
	arguments, constraints := "<16 x i8> "+source, "=w,w"
	oldWidth := 0
	if form.highHalf {
		oldWidth = 64 // The *2 form preserves the low half.
		mnemonic += "2"
	}
	if mergeScalar {
		oldWidth = 128 // With FEAT_AFP, FPCR.NEP can preserve the upper lanes.
	}
	if oldWidth != 0 {
		old, err := c.loadVRegWidth(destination, oldWidth)
		if err != nil {
			return err
		}
		arguments += ", <16 x i8> " + old
		constraints += ",0"
	}
	assembly := fmt.Sprintf("%s %s, %s", mnemonic, arm64NativeSIMDReg(0, destinationView), arm64NativeSIMDReg(1, sourceView))
	if shift != 0 {
		assembly += fmt.Sprintf(", #%d", shift)
	}
	// Preserve the FPSR effects even when the numerical result is unused.
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s)\n",
		result, assembly, constraints+",~{memory}", arguments)
	return c.storeVReg(destination, "%"+result)
}
