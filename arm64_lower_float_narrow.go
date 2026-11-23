package plan9asm

import (
	"fmt"
	"strings"
)

type arm64FloatNarrowForm struct {
	arm64NarrowOperands
	roundOdd bool
}

func decodeARM64RawFloatNarrow(word uint32) (arm64FloatNarrowForm, bool) {
	const q = 1 << 30
	form := arm64FloatNarrowForm{
		arm64NarrowOperands: arm64NarrowOperands{
			source: int(word >> 5 & 31), destination: int(word & 31),
			highHalf: word&q != 0,
		},
	}
	switch {
	case word&0xbfbffc00 == 0x0e216800:
		form.bits = 16 << (word >> 22 & 1)
	case word&0xbffffc00 == 0x2e616800:
		form.bits, form.roundOdd = 32, true
	case word&0xfffffc00 == 0x7e616800:
		form.bits, form.roundOdd = 32, true
		form.scalar, form.highHalf = true, false
	default:
		return arm64FloatNarrowForm{}, false
	}
	return form, true
}

func (c *arm64Ctx) lowerARM64VectorFloatNarrow(op Op, ins Instr) (bool, bool, error) {
	if op != "VFCVTN" && op != "VFCVTN2" {
		return false, false, nil
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vsrc.S4/D2 and the corresponding narrow destination and no suffix: %q", op, ins.Raw)
	}
	source, sourceOK := parseARM64VectorArrangement(ins.Args[0].Reg)
	destination, destinationOK := parseARM64VectorArrangement(ins.Args[1].Reg)
	invalid := func() (bool, bool, error) {
		return true, false, fmt.Errorf("arm64 %s operand arrangements are outside Go 1.27's narrowing optab: %q", op, ins.Raw)
	}
	if !sourceOK || !destinationOK || source.elementBits < 32 {
		return invalid()
	}
	form := arm64FloatNarrowForm{
		arm64NarrowOperands: arm64NarrowOperands{bits: source.elementBits / 2, highHalf: op == "VFCVTN2"},
	}
	wantSource, wantDestination := form.arrangements()
	if source != wantSource || destination != wantDestination {
		return invalid()
	}
	form.source, _ = arm64ParseVReg(ins.Args[0].Reg)
	form.destination, _ = arm64ParseVReg(ins.Args[1].Reg)
	return true, false, c.lowerARM64FloatNarrow(form)
}

func (c *arm64Ctx) lowerARM64FloatNarrow(form arm64FloatNarrowForm) error {
	if arm64ScalarConversionNativeTarget(c.targetTriple) {
		mnemonic := "fcvtn"
		if form.roundOdd {
			mnemonic = "fcvtxn"
		}
		return c.lowerARM64NativeNarrow(form.arm64NarrowOperands, mnemonic, 0, form.scalar)
	}
	if form.roundOdd {
		return fmt.Errorf("%w: ARM64 FCVTXN requires a native little-endian AArch64 floating-point target", ErrProbeNeedsContext)
	}

	sourceView, destinationView := form.arrangements()
	source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), sourceView)
	if err != nil {
		return err
	}
	sourceType := fmt.Sprintf("<%d x %s>", sourceView.lanes, arm64RawFloatType(sourceView.elementBits))
	narrowType := fmt.Sprintf("<%d x %s>", sourceView.lanes, arm64RawFloatType(form.bits))
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fptrunc %s %s to %s\n", converted, sourceType, source, narrowType)
	result := "%" + converted
	destination := Reg(fmt.Sprintf("V%d", form.destination))
	if form.highHalf {
		low := arm64VectorArrangement{form.bits, sourceView.lanes}
		old, err := c.loadARM64VectorFloat(destination, low)
		if err != nil {
			return err
		}
		indices := make([]int, destinationView.lanes)
		for i := range indices {
			indices[i] = i
		}
		result = c.arm64StructureShuffle(narrowType, old, result, indices)
	}
	return c.storeARM64VectorFloat(destination, destinationView, result)
}
