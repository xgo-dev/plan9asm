package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
)

type arm64SaturatingShiftForm struct {
	op          string
	arrangement arm64VectorArrangement
	scalar      bool
	source      int
	destination int
	shiftReg    int
	immediate   bool
	shift       int
}

func (c *arm64Ctx) lowerARM64VectorSaturatingShift(op Op, ins Instr) (bool, bool, error) {
	// The Go optab has only the arranged SQSHL and UQSHL rows. Scalar,
	// rounded and signed-to-unsigned forms are available through WORD.
	if op != "VSQSHL" && op != "VUQSHL" {
		return false, false, nil
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects $shift|Vshifts.T, Vvalue.T, Vdst.T with no suffix: %q", op, ins.Raw)
	}
	form := arm64SaturatingShiftForm{op: strings.ToLower(string(op[1:])), immediate: ins.Args[0].Kind == OpImm}
	var registers [3]int
	for index, operand := range ins.Args {
		if index == 0 && form.immediate {
			continue
		}
		reg, register := arm64ParseVReg(operand.Reg)
		arrangement, arranged := parseARM64VectorArrangement(operand.Reg)
		if operand.Kind != OpReg || !register || !arranged || !arm64IntegerShiftVectorArrangement(arrangement) {
			return true, false, fmt.Errorf("arm64 %s requires B8/B16/H4/H8/S2/S4/D2 vector operands: %q", op, ins.Raw)
		}
		if form.arrangement.lanes != 0 && form.arrangement != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
		form.arrangement = arrangement
		registers[index] = reg
	}
	form.shiftReg, form.source, form.destination = registers[0], registers[1], registers[2]
	if form.immediate {
		shift := ins.Args[0]
		if shift.ImmRaw != "" || shift.ImmIsFloat || shift.Imm < 0 || shift.Imm >= int64(form.arrangement.elementBits) {
			return true, false, fmt.Errorf("arm64 %s immediate must be in [0,%d): %q", op, form.arrangement.elementBits, ins.Raw)
		}
		form.shift = int(shift.Imm)
	}
	return true, false, c.lowerARM64SaturatingShift(form)
}

func arm64IntegerShiftVectorArrangement(arrangement arm64VectorArrangement) bool {
	switch arrangement.elementBits {
	case 8, 16, 32, 64:
		width := arrangement.elementBits * arrangement.lanes
		return width == 128 || width == 64 && arrangement.elementBits != 64
	}
	return false
}

// Q is required by the scalar encoding; for vectors it selects 64/128 bits.
// Register counts use size, while immediate forms encode elementBits+shift.
func decodeARM64RawSaturatingShift(word uint32) (arm64SaturatingShiftForm, bool) {
	const (
		scalarBit       = 1 << 28
		qBit            = 1 << 30
		unsignedBit     = 1 << 29
		viewFields      = scalarBit | qBit | unsignedBit
		lowRegisters    = 31<<5 | 31
		immediateFields = viewFields | 0x7f<<16 | lowRegisters
		registerFields  = viewFields | 3<<22 | 31<<16 | lowRegisters | 1<<12
	)
	form := arm64SaturatingShiftForm{
		op: "sqshl", scalar: word&scalarBit != 0,
		source: int(word >> 5 & 31), destination: int(word & 31),
	}
	wide := word&qBit != 0
	if form.scalar && !wide {
		return arm64SaturatingShiftForm{}, false
	}
	if word&unsignedBit != 0 {
		form.op = "uqshl"
	}
	var elementBits int
	switch {
	case word&^registerFields == 0x0e204c00:
		elementBits = 8 << (word >> 22 & 3)
		form.shiftReg = int(word >> 16 & 31)
		if word&(1<<12) != 0 {
			form.op = form.op[:2] + "rshl"
		}
	case word&^immediateFields == 0x0f007400,
		word&^immediateFields == 0x0f006400 && word&unsignedBit != 0:
		encoded := int(word >> 16 & 127)
		if encoded < 8 {
			return arm64SaturatingShiftForm{}, false
		}
		elementBits = 1 << (bits.Len8(uint8(encoded)) - 1)
		form.immediate = true
		form.shift = encoded - elementBits
		if word&(1<<12) == 0 {
			form.op = "sqshlu"
		}
	default:
		return arm64SaturatingShiftForm{}, false
	}

	lanes := 1
	if !form.scalar {
		vectorBits := 64
		if wide {
			vectorBits = 128
		}
		lanes = vectorBits / elementBits
	}
	form.arrangement = arm64VectorArrangement{elementBits: elementBits, lanes: lanes}
	if !form.scalar && !arm64IntegerShiftVectorArrangement(form.arrangement) {
		return arm64SaturatingShiftForm{}, false
	}
	return form, true
}

func (c *arm64Ctx) lowerARM64SaturatingShift(form arm64SaturatingShiftForm) error {
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 %s requires a native little-endian AArch64 FPSR target", ErrProbeNeedsContext, form.op)
	}
	elementBits := form.arrangement.elementBits
	width := form.arrangement.lanes * elementBits
	value, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.source)), width)
	if err != nil {
		return err
	}
	assembly := fmt.Sprintf("%s %s, %s, ", form.op,
		arm64NativeSIMDReg(0, form.arrangement), arm64NativeSIMDReg(1, form.arrangement))
	constraints, arguments := "=w,w,~{memory}", "<16 x i8> "+value
	if form.immediate {
		assembly += fmt.Sprintf("#%d", form.shift)
	} else {
		countWidth := width
		if form.scalar {
			countWidth = 8 // Scalar shifts consume the signed low byte.
		}
		shifts, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.shiftReg)), countWidth)
		if err != nil {
			return err
		}
		assembly += arm64NativeSIMDReg(2, form.arrangement)
		constraints, arguments = "=w,w,w,~{memory}", arguments+", <16 x i8> "+shifts
	}

	// The result may be dead, but saturation still changes the sticky QC
	// bit. Use the actual instruction and order it with native FPSR transfers.
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s)\n",
		result, assembly, constraints, arguments)
	return c.storeVReg(Reg(fmt.Sprintf("V%d", form.destination)), "%"+result)
}
