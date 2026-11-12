package plan9asm

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
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 || p.opcode < 0x78 || p.opcode > 0x7b {
		return Instr{}, 0, false, nil
	}
	return decodedX86PackedNumericConversionInstruction(code, mode)
}
