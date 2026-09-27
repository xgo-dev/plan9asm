package plan9asm

import (
	"fmt"
	"strings"
)

// The eight packed float-to-(u)int64 conversions share Go 1.27's
// _yvcvtps2qq and _yvcvtpd2qq grammars. Their source width is determined
// by the float lane size and destination width, with common mask, zeroing,
// broadcast, and embedded rounding/SAE rules.
var x86RawPackedWidenConversionByOpcode = map[int]Op{
	0x7b: "VCVTPS2QQ",
	0x79: "VCVTPS2UQQ",
	0x7a: "VCVTTPS2QQ",
	0x78: "VCVTTPS2UQQ",
}

var x86RawPackedDoubleConversionByOpcode = map[int]Op{
	0x7b: "VCVTPD2QQ",
	0x79: "VCVTPD2UQQ",
	0x7a: "VCVTTPD2QQ",
	0x78: "VCVTTPD2UQQ",
}

func decodedX86PackedWidenConversionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	ops := x86RawPackedWidenConversionByOpcode
	if p.w {
		ops = x86RawPackedDoubleConversionByOpcode
	}
	op, matched := ops[p.opcode]
	if !matched {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed widening conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.segment != "" || p.upper != 0 {
		return fail("invalid EVEX prefix or source-layout-unsafe address")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	registerSource := modRM>>6 == 3
	embedded := p.broadcast && registerSource
	if p.vectorLength > 2 && !embedded {
		return fail("reserved EVEX vector length")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	destinationWidth := p.vectorLength
	if embedded {
		destinationWidth = 2
	}
	destinationPrefix := [...]string{"X", "Y", "Z"}[destinationWidth]
	sourcePrefix := "X"
	if p.w {
		sourcePrefix = destinationPrefix
	} else if destinationWidth == 2 {
		sourcePrefix = "Y"
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || registerSource && (p.b != 0 || p.x != 0)) {
		return fail("extended vector register in 32-bit mode")
	}
	scale := 8 << destinationWidth
	if p.w {
		scale *= 2
	}
	if p.broadcast && !registerSource {
		scale = 4
		if p.w {
			scale = 8
		}
	}
	source, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix, scale,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if embedded {
		if strings.HasPrefix(string(op), "VCVTT") {
			op += ".SAE"
		} else {
			op += Op("." + [...]string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"}[p.vectorLength])
		}
	} else if p.broadcast {
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationPrefix, destinationNumber))})
	rawArgs := make([]string, len(args))
	for index, arg := range args {
		rawArgs[index] = arg.String()
	}
	return Instr{
		Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(rawArgs, ", ")),
		x86Encoded: true,
	}, p.modRM + consumed, true, nil
}
