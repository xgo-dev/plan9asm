package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SaturatingInputs uint8

const (
	arm64SaturatingUnary arm64SaturatingInputs = iota
	arm64SaturatingBinary
	arm64SaturatingAccumulator
)

type arm64SaturatingArithmeticOp struct {
	name      Op // Empty for WORD-only forms.
	mnemonic  string
	encoding  uint32
	inputs    arm64SaturatingInputs
	intrinsic string
}

var arm64SaturatingArithmeticOps = [...]arm64SaturatingArithmeticOp{
	{name: "VSQADD", mnemonic: "sqadd", encoding: 0x0e200c00, inputs: arm64SaturatingBinary, intrinsic: "sadd.sat"},
	{name: "VUQADD", mnemonic: "uqadd", encoding: 0x2e200c00, inputs: arm64SaturatingBinary, intrinsic: "uadd.sat"},
	{name: "VSQSUB", mnemonic: "sqsub", encoding: 0x0e202c00, inputs: arm64SaturatingBinary, intrinsic: "ssub.sat"},
	{name: "VUQSUB", mnemonic: "uqsub", encoding: 0x2e202c00, inputs: arm64SaturatingBinary, intrinsic: "usub.sat"},
	{name: "VSQABS", mnemonic: "sqabs", encoding: 0x0e207800, inputs: arm64SaturatingUnary},
	{name: "VSQNEG", mnemonic: "sqneg", encoding: 0x2e207800, inputs: arm64SaturatingUnary},
	{mnemonic: "suqadd", encoding: 0x0e203800, inputs: arm64SaturatingAccumulator},
	{mnemonic: "usqadd", encoding: 0x2e203800, inputs: arm64SaturatingAccumulator},
}

type arm64SaturatingArithmeticForm struct {
	op            *arm64SaturatingArithmeticOp
	arrangement   arm64VectorArrangement
	first, second int
	destination   int
}

func decodeARM64RawSaturatingArithmetic(word uint32) (arm64SaturatingArithmeticForm, bool) {
	const scalarBit, qBit = 1 << 28, 1 << 30
	const commonFields = scalarBit | qBit | 3<<22 | 31<<5 | 31
	scalar, wide := word&scalarBit != 0, word&qBit != 0
	bits := 8 << (word >> 22 & 3)
	if !wide && (scalar || bits == 64) {
		return arm64SaturatingArithmeticForm{}, false
	}
	lanes := 1
	if !scalar {
		lanes = 64 / bits
		if wide {
			lanes *= 2
		}
	}
	for i := range arm64SaturatingArithmeticOps {
		op := &arm64SaturatingArithmeticOps[i]
		fields := uint32(commonFields)
		if op.inputs == arm64SaturatingBinary {
			fields |= 31 << 16
		}
		if word&^fields == op.encoding {
			return arm64SaturatingArithmeticForm{
				op: op, arrangement: arm64VectorArrangement{bits, lanes},
				first: int(word >> 5 & 31), second: int(word >> 16 & 31),
				destination: int(word & 31),
			}, true
		}
	}
	return arm64SaturatingArithmeticForm{}, false
}

func (c *arm64Ctx) lowerARM64VectorSaturatingArithmetic(op Op, ins Instr) (bool, bool, error) {
	var spec *arm64SaturatingArithmeticOp
	for i := range arm64SaturatingArithmeticOps {
		candidate := &arm64SaturatingArithmeticOps[i]
		if candidate.name != "" && candidate.name == op {
			spec = candidate
			break
		}
	}
	if spec == nil {
		return false, false, nil
	}
	count := 2
	if spec.inputs == arm64SaturatingBinary {
		count = 3
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != count {
		return true, false, fmt.Errorf("arm64 %s expects %d same-arrangement vector registers and no suffix: %q", op, count, ins.Raw)
	}

	form := arm64SaturatingArithmeticForm{op: spec}
	var registers [3]int
	for i, arg := range ins.Args {
		reg, validRegister := arm64ParseVReg(arg.Reg)
		arrangement, arranged := parseARM64VectorArrangement(arg.Reg)
		if arg.Kind != OpReg || !validRegister || !arranged || arrangement.elementBits == 64 && arrangement.lanes != 2 {
			return true, false, fmt.Errorf("arm64 %s accepts only B8/B16/H4/H8/S2/S4/D2 arrangements: %q", op, ins.Raw)
		}
		if i > 0 && form.arrangement != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
		form.arrangement = arrangement
		registers[i] = reg
	}
	form.first, form.destination = registers[0], registers[count-1]
	if spec.inputs == arm64SaturatingBinary {
		form.first, form.second = registers[1], registers[0]
	}
	return true, false, c.lowerARM64SaturatingArithmetic(form)
}

func (c *arm64Ctx) lowerARM64SaturatingArithmetic(form arm64SaturatingArithmeticForm) error {
	arrangement := form.arrangement
	firstReg := Reg(fmt.Sprintf("V%d", form.first))
	destination := Reg(fmt.Sprintf("V%d", form.destination))
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return c.lowerARM64PortableSaturatingArithmetic(form, firstReg, destination)
	}

	width := arrangement.lanes * arrangement.elementBits
	first, err := c.loadVRegWidth(firstReg, width)
	if err != nil {
		return err
	}
	assembly := fmt.Sprintf("%s %s, %s", form.op.mnemonic,
		arm64NativeSIMDReg(0, arrangement), arm64NativeSIMDReg(1, arrangement))
	arguments, constraints := "<16 x i8> "+first, "=w,w"
	switch form.op.inputs {
	case arm64SaturatingBinary:
		second, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", form.second)), width)
		if err != nil {
			return err
		}
		assembly += ", " + arm64NativeSIMDReg(2, arrangement)
		arguments += ", <16 x i8> " + second
		constraints += ",w"
	case arm64SaturatingAccumulator:
		old, err := c.loadVRegWidth(destination, width)
		if err != nil {
			return err
		}
		arguments += ", <16 x i8> " + old
		constraints += ",0"
	}
	// The instruction can set sticky FPSR.QC even when its result is dead.
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s)\n",
		result, assembly, constraints+",~{memory}", arguments)
	return c.storeVReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64PortableSaturatingArithmetic(form arm64SaturatingArithmeticForm, source, destination Reg) error {
	if form.op.inputs == arm64SaturatingAccumulator {
		return c.lowerARM64PortableMixedSaturatingAdd(form, source, destination)
	}
	arrangement := form.arrangement
	if arrangement.lanes == 1 {
		return fmt.Errorf("%w: ARM64 %s scalar saturation requires a native little-endian AArch64 FPSR target",
			ErrProbeNeedsContext, form.op.mnemonic)
	}
	if form.op.inputs == arm64SaturatingUnary {
		return c.lowerARM64IntegerAbsNeg(source, destination, arrangement, form.op.mnemonic == "sqabs", true)
	}
	left, err := c.loadARM64VectorInteger(source, arrangement)
	if err != nil {
		return err
	}
	right, err := c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d", form.second)), arrangement)
	if err != nil {
		return err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%di%d(%s %s, %s %s)\n",
		result, vectorType, form.op.intrinsic, arrangement.lanes, arrangement.elementBits, vectorType, left, vectorType, right)
	return c.storeARM64VectorInteger(destination, arrangement, "%"+result)
}
