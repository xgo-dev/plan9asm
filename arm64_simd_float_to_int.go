package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SIMDFloatToIntForm struct {
	rounding    arm64FloatToIntegerRounding
	unsigned    bool
	arrangement arm64VectorArrangement // One lane denotes the scalar encoding.
	source      int
	destination int
}

// The scalar and packed Advanced SIMD encodings share the precision,
// rounding, signedness and register fields. The scalar selector requires Q=1
// and the packed 64-bit element encoding also requires Q=1.
func decodeARM64RawSIMDFloatToInt(word uint32) (arm64SIMDFloatToIntForm, bool) {
	const registers = 31 | 31<<5
	const unsigned = 1 << 29
	const precision = 0x00780000
	const scalar = 1 << 28
	const q = 1 << 30

	var rounding arm64FloatToIntegerRounding
	switch word &^ (registers | unsigned | precision | scalar | q) {
	case 0x0e01a800:
		rounding = arm64FloatRoundNearestEven
	case 0x0e01c800:
		rounding = arm64FloatRoundTiesAway
	case 0x0e81a800:
		rounding = arm64FloatRoundPlusInf
	case 0x0e01b800:
		rounding = arm64FloatRoundMinusInf
	case 0x0e81b800:
		rounding = arm64FloatRoundZero
	default:
		return arm64SIMDFloatToIntForm{}, false
	}

	var bits int
	switch word & precision {
	case 0x00780000:
		bits = 16
	case 0x00200000:
		bits = 32
	case 0x00600000:
		bits = 64
	default:
		return arm64SIMDFloatToIntForm{}, false
	}

	lanes := 1
	if word&q == 0 && (word&scalar != 0 || bits == 64) {
		return arm64SIMDFloatToIntForm{}, false
	}
	if word&scalar == 0 {
		vectorBits := 64
		if word&q != 0 {
			vectorBits = 128
		}
		lanes = vectorBits / bits
	}
	return arm64SIMDFloatToIntForm{
		rounding:    rounding,
		unsigned:    word&unsigned != 0,
		arrangement: arm64VectorArrangement{elementBits: bits, lanes: lanes},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

type arm64VectorFloatToIntSpec struct {
	rounding arm64FloatToIntegerRounding
	unsigned bool
}

var arm64VectorFloatToIntOps = map[Op]arm64VectorFloatToIntSpec{
	"VFCVTNS": {arm64FloatRoundNearestEven, false},
	"VFCVTNU": {arm64FloatRoundNearestEven, true},
	"VFCVTAS": {arm64FloatRoundTiesAway, false},
	"VFCVTAU": {arm64FloatRoundTiesAway, true},
	"VFCVTPS": {arm64FloatRoundPlusInf, false},
	"VFCVTPU": {arm64FloatRoundPlusInf, true},
	"VFCVTMS": {arm64FloatRoundMinusInf, false},
	"VFCVTMU": {arm64FloatRoundMinusInf, true},
	"VFCVTZS": {arm64FloatRoundZero, false},
	"VFCVTZU": {arm64FloatRoundZero, true},
}

func parseARM64VectorFloatToInt(op Op, instruction Instr) (arm64SIMDFloatToIntForm, bool, error) {
	spec, known := arm64VectorFloatToIntOps[op]
	if !known {
		return arm64SIMDFloatToIntForm{}, false, nil
	}
	if strings.ToUpper(string(instruction.Op)) != string(op) || len(instruction.Args) != 2 ||
		instruction.Args[0].Kind != OpReg || instruction.Args[1].Kind != OpReg {
		return arm64SIMDFloatToIntForm{}, true, fmt.Errorf("arm64 %s expects two vector registers and no suffix: %q", op, instruction.Raw)
	}
	src, dst := instruction.Args[0].Reg, instruction.Args[1].Reg
	arrangement, srcValid := parseARM64VectorArrangement(src)
	destination, dstValid := parseARM64VectorArrangement(dst)
	// Go's text forms use S2, S4 and D2. FP16 is available as WORD.
	if !srcValid || !dstValid || arrangement != destination ||
		!(arrangement.elementBits == 32 || arrangement.elementBits == 64 && arrangement.lanes == 2) {
		return arm64SIMDFloatToIntForm{}, true, fmt.Errorf("arm64 %s requires matching S2, S4, or D2 arrangements: %q", op, instruction.Raw)
	}
	srcIndex, _ := arm64ParseVReg(src)
	dstIndex, _ := arm64ParseVReg(dst)
	return arm64SIMDFloatToIntForm{
		rounding: spec.rounding, unsigned: spec.unsigned, arrangement: arrangement,
		source: srcIndex, destination: dstIndex,
	}, true, nil
}

func arm64FloatToIntegerMnemonic(rounding arm64FloatToIntegerRounding, unsigned bool) string {
	modes := [...]string{"fcvtn", "fcvta", "fcvtp", "fcvtm", "fcvtz"}
	if int(rounding) >= len(modes) {
		return ""
	}
	if unsigned {
		return modes[rounding] + "u"
	}
	return modes[rounding] + "s"
}

func (c *arm64Ctx) lowerARM64SIMDFloatToInt(form arm64SIMDFloatToIntForm) error {
	bits, lanes := form.arrangement.elementBits, form.arrangement.lanes
	if lanes == 1 {
		return c.lowerARM64ScalarConversion(arm64ScalarConversionForm{
			arm64ScalarConversionSpec: arm64ScalarConversionSpec{
				floatBits: bits, integerBits: bits, unsigned: form.unsigned, simdInteger: true,
			},
			source: Reg(fmt.Sprintf("F%d", form.source)), destination: Reg(fmt.Sprintf("F%d", form.destination)),
			rounding: form.rounding,
		})
	}

	opcode := arm64FloatToIntegerMnemonic(form.rounding, form.unsigned)
	return c.lowerARM64VectorConversion(opcode, form.arrangement, form.source, form.destination, 0)
}

func (c *arm64Ctx) lowerARM64VectorConversion(opcode string, arrangement arm64VectorArrangement, src, dst, fraction int) error {
	bits, lanes := arrangement.elementBits, arrangement.lanes
	source, err := c.loadVRegWidth(Reg(fmt.Sprintf("V%d", src)), bits*lanes)
	if err != nil {
		return err
	}
	layout := fmt.Sprintf("%d%s", lanes, arm64ScalarConversionModifier(bits, false))
	operation := arm64ConversionWithFraction(fmt.Sprintf("%s $0.%s, $1.%s", opcode, layout, layout), fraction)
	result := c.newTmp()
	// Native writes define the full V register, including the zeroed upper
	// half after a 64-bit form. FPSR survives unused results.
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(<16 x i8> %s)\n",
		result, operation, "=w,w,~{memory}", source)
	return c.storeVReg(Reg(fmt.Sprintf("V%d", dst)), "%"+result)
}
