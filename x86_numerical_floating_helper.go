package plan9asm

type x86FloatingHelperEncoding uint8

const (
	x86HelperScalar x86FloatingHelperEncoding = 1 << iota
	x86HelperSecond
	x86HelperSAE
	x86HelperRound
	x86HelperMaskResult
	x86Helper512
)

// Packed and scalar pairs share their controls across both W precisions.
// V is reserved for unary packed forms and for every FPCLASS form.
func x86FloatingHelperEncodingFor(mapNumber, opcode int) (x86FloatingHelperEncoding, bool) {
	switch mapNumber<<8 | opcode {
	case 0x24c, 0x24e: // RCP14, RSQRT14
		return 0, true
	case 0x24d, 0x24f:
		return x86HelperScalar | x86HelperSecond, true
	case 0x242, 0x308, 0x309, 0x326, 0x356: // GETEXP, RNDSCALE, GETMANT, REDUCE
		return x86HelperSAE, true
	case 0x243, 0x2cb, 0x2cd, 0x30a, 0x30b, 0x327, 0x357:
		return x86HelperScalar | x86HelperSecond | x86HelperSAE, true
	case 0x2c8, 0x2ca, 0x2cc: // EXP2, RCP28, RSQRT28
		return x86Helper512 | x86HelperSAE, true
	case 0x22c, 0x22d: // SCALEF
		flags := x86HelperSecond | x86HelperRound
		if opcode == 0x2d {
			flags |= x86HelperScalar
		}
		return flags, true
	case 0x350, 0x354: // RANGE, FIXUPIMM
		return x86HelperSecond | x86HelperSAE, true
	case 0x351, 0x355:
		return x86HelperScalar | x86HelperSecond | x86HelperSAE, true
	case 0x366: // FPCLASS
		return x86HelperMaskResult, true
	case 0x367:
		return x86HelperScalar | x86HelperMaskResult, true
	default:
		return 0, false
	}
}

// These bytes belong to an independently paired Go source instruction. Return
// only its boundary so a raw stream cannot acquire named-source authority.
func decodedX86NumericalFloatingHelperBoundary(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	form, known := x86FloatingHelperEncodingFor(p.mapNumber, p.opcode)
	if !known {
		return Instr{}, 0, false, nil
	}
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, numericalSBContext("EVEX floating helper: " + reason)
	}
	if (mode != 32 && mode != 64) || !p.fixed || p.addressOverride || len(code) <= p.modRM ||
		form&x86HelperSecond == 0 && p.upper != 0 || p.zero && p.mask == 0 ||
		form&x86HelperMaskResult != 0 && (p.zero || p.r != 0) ||
		mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("invalid prefix, mask, or register bank")
	}
	if p.mapNumber == 3 && p.opcode >= 8 && p.opcode <= 0x0b && p.w != (p.opcode&1 != 0) {
		return fail("invalid RNDSCALE precision bit")
	}
	scalar := form&x86HelperScalar != 0
	register := code[p.modRM]>>6 == 3
	length := p.vectorLength
	if p.broadcast && register && form&x86HelperRound != 0 {
		length = 2 // Embedded rounding occupies LL; packed SCALEF is then Z.
		if scalar {
			length = 0
		}
	}
	if length > 2 || scalar && length != 0 || form&x86Helper512 != 0 && length != 2 ||
		p.broadcast && register && (form&(x86HelperSAE|x86HelperRound) == 0 || !scalar && length != 2) ||
		p.broadcast && !register && scalar {
		return fail("invalid width or EVEX.b control")
	}
	scale := 16 << length
	if scalar || p.broadcast {
		scale = 4
		if p.w {
			scale = 8
		}
	}
	prefix := [...]string{"X", "Y", "Z"}[length]
	_, consumed, err := memory.evex(code[p.modRM:], mode, p.b, p.x, p.segment, prefix, scale)
	if err != nil {
		return Instr{}, 0, true, err
	}
	end := p.modRM + consumed
	if p.mapNumber == 3 {
		if end == len(code) {
			return fail("missing imm8")
		}
		end++
	}
	return Instr{}, end, true, nil
}
