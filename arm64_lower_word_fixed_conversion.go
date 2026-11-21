package plan9asm

import "fmt"

type arm64FixedConversionForm struct {
	toFloat, unsigned, gp  bool
	floatBits, integerBits int
	lanes, fractionalBits  int
	source, destination    int
}

func decodeARM64RawFixedConversion(word uint32) (arm64FixedConversionForm, bool) {
	const registers = 31 | 31<<5
	const gpFields = 1<<31 | 3<<22 | 1<<16 | 63<<10 | registers
	switch opcode := word &^ gpFields; opcode {
	case 0x1e020000, 0x1e180000: // SCVTF/UCVTF and FCVTZS/FCVTZU.
		floatBits := 0
		switch word >> 22 & 3 {
		case 0:
			floatBits = 32
		case 1:
			floatBits = 64
		case 3:
			floatBits = 16
		default:
			return arm64FixedConversionForm{}, false
		}
		integerBits := 32
		if word&(1<<31) != 0 {
			integerBits = 64
		}
		fraction := 64 - int(word>>10&63)
		if fraction > integerBits {
			return arm64FixedConversionForm{}, false
		}
		return arm64FixedConversionForm{
			toFloat: opcode == 0x1e020000, unsigned: word&(1<<16) != 0, gp: true,
			floatBits: floatBits, integerBits: integerBits, lanes: 1, fractionalBits: fraction,
			source: int(word>>5) & 31, destination: int(word) & 31,
		}, true
	}

	const scalar = 1 << 28
	const q = 1 << 30
	const simdFields = scalar | q | 1<<29 | 127<<16 | registers
	opcode := word &^ simdFields
	if opcode != 0x0f00e400 && opcode != 0x0f00fc00 {
		return arm64FixedConversionForm{}, false
	}

	// The most significant set bit in immh selects the element width.
	// Together immh:immb encodes twice that width minus the fraction.
	immediate := int(word >> 16 & 127)
	var bits int
	switch {
	case immediate >= 64:
		bits = 64
	case immediate >= 32:
		bits = 32
	case immediate >= 16:
		bits = 16
	default:
		return arm64FixedConversionForm{}, false
	}
	if word&q == 0 && (word&scalar != 0 || bits == 64) {
		return arm64FixedConversionForm{}, false
	}
	lanes := 1
	if word&scalar == 0 {
		vectorBits := 64
		if word&q != 0 {
			vectorBits = 128
		}
		lanes = vectorBits / bits
	}
	return arm64FixedConversionForm{
		toFloat: opcode == 0x0f00e400, unsigned: word&(1<<29) != 0,
		floatBits: bits, integerBits: bits, lanes: lanes, fractionalBits: 2*bits - immediate,
		source: int(word>>5) & 31, destination: int(word) & 31,
	}, true
}

func (form arm64FixedConversionForm) registers() (source, destination Reg) {
	register := func(index int, gp bool) Reg {
		if !gp {
			return Reg(fmt.Sprintf("F%d", index))
		}
		if index == 31 {
			return ZR
		}
		return Reg(fmt.Sprintf("R%d", index))
	}
	return register(form.source, form.gp && form.toFloat), register(form.destination, form.gp && !form.toFloat)
}

func (c *arm64Ctx) lowerRawFixedConversion(form arm64FixedConversionForm) error {
	if form.lanes > 1 {
		arrangement := arm64VectorArrangement{elementBits: form.floatBits, lanes: form.lanes}
		opcode := arm64FloatToIntegerMnemonic(arm64FloatRoundZero, form.unsigned)
		if form.toFloat {
			opcode = arm64IntegerToFloatMnemonic(form.unsigned)
		}
		return c.lowerARM64VectorConversion(opcode, arrangement, form.source, form.destination, form.fractionalBits)
	}
	source, destination := form.registers()
	return c.lowerARM64ScalarConversion(arm64ScalarConversionForm{
		arm64ScalarConversionSpec: arm64ScalarConversionSpec{
			floatBits: form.floatBits, integerBits: form.integerBits,
			toFloat: form.toFloat, unsigned: form.unsigned, simdInteger: !form.gp,
		},
		source: source, destination: destination, rounding: arm64FloatRoundZero, fraction: form.fractionalBits,
	})
}
