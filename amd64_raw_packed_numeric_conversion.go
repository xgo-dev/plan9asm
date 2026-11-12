package plan9asm

import (
	"fmt"
	"strings"
)

// Opcode/mandatory-prefix/W select an element conversion. VL selects a
// physical shape in the shared source grammar; it is not a separate opcode.
func x86RawPackedNumericName(p x86RawVectorEncoding) Op {
	if p.mapNumber != 1 {
		return ""
	}
	if !p.evex {
		switch {
		case p.opcode == 0x5b && p.pp == 1:
			return "VCVTPS2DQ"
		case p.opcode == 0x5b && p.pp == 2:
			return "VCVTTPS2DQ"
		case p.opcode == 0xe6 && p.pp == 3:
			return "VCVTPD2DQ"
		case p.opcode == 0xe6 && p.pp == 1:
			return "VCVTTPD2DQ"
		}
		return "" // These VEX encodings are WIG, including in mode32.
	}
	if p.pp == 1 && p.opcode >= 0x78 && p.opcode <= 0x7b {
		names := [...]Op{"VCVTTPS2UQQ", "VCVTPS2UQQ", "VCVTTPS2QQ", "VCVTPS2QQ"}
		name := names[p.opcode-0x78]
		if p.w {
			name = Op(strings.Replace(string(name), "PS", "PD", 1))
		}
		return name
	}
	switch {
	case p.opcode == 0x5b && p.pp == 1 && !p.w:
		return "VCVTPS2DQ"
	case p.opcode == 0x5b && p.pp == 2 && !p.w:
		return "VCVTTPS2DQ"
	case p.opcode == 0xe6 && p.pp == 3 && p.w:
		return "VCVTPD2DQ"
	case p.opcode == 0xe6 && p.pp == 1 && p.w:
		return "VCVTTPD2DQ"
	case (p.opcode == 0x78 || p.opcode == 0x79) && p.pp == 0:
		name := "VCVT"
		if p.opcode == 0x78 {
			name += "T"
		}
		if p.w {
			return Op(name + "PD2UDQ")
		}
		return Op(name + "PS2UDQ")
	case p.opcode == 0x7a && p.pp == 2 && !p.w:
		return "VCVTUDQ2PD"
	case p.opcode == 0x7a && p.pp == 3 && !p.w:
		return "VCVTUDQ2PS"
	case p.opcode == 0xe6 && p.pp == 2 && p.w:
		return "VCVTQQ2PD"
	case p.opcode == 0x7a && p.pp == 2 && p.w:
		return "VCVTUQQ2PD"
	case p.opcode == 0x5b && p.pp == 0 && p.w:
		return "VCVTQQ2PS"
	case p.opcode == 0x7a && p.pp == 3 && p.w:
		return "VCVTUQQ2PS"
	}
	return ""
}

func decodedX86PackedNumericConversionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86PackedNumericConversionInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86PackedNumericConversionInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched {
		return Instr{}, 0, false, nil
	}
	name := x86RawPackedNumericName(p)
	if name == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed numeric conversion: %s", reason)
	}
	if mode != 32 && mode != 64 || p.addressOverride || p.upper != 0 ||
		p.evex && (!p.fixed || p.zero && p.mask == 0) || len(code) <= p.modRM {
		return fail("invalid physical mode, prefix, reserved field, or truncated ModRM")
	}
	register := code[p.modRM]>>6 == 3
	embedded := p.evex && p.broadcast && register
	vl := p.vectorLength
	if embedded {
		vl = 2
	}
	if vl > 2 || !p.evex && vl > 1 {
		return fail("reserved vector length")
	}
	spec, _ := x86PackedConversionSpecification(name)
	if spec.sourceBits > spec.destinationBits && vl < 2 {
		name += [...]Op{"X", "Y"}[vl]
		spec, _ = x86PackedConversionSpecification(name)
	}
	shape := spec.shapes[0]
	if len(spec.shapes) > 1 {
		shape = spec.shapes[vl]
	}
	if embedded && spec.explicit == "" {
		return fail("embedded rounding/SAE absent from this conversion")
	}
	width := shape.lanes * spec.sourceBits / 8
	if p.broadcast && !register {
		width = spec.sourceBits / 8
	}
	prefix := map[int]string{16: "X", 32: "Y", 64: "Z"}
	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = memory.evex(code[p.modRM:], mode, p.b, p.x, p.segment, prefix[shape.sourceBytes], width)
	} else {
		source, consumed, err = memory.vex(code[p.modRM:], mode, p.b, p.x, p.segment, prefix[shape.sourceBytes])
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	if embedded {
		if spec.explicit == "sae" {
			name += ".SAE" // LL is ignored for SAE-only register encodings.
		} else {
			name += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
		}
	} else if p.broadcast {
		name += ".BCST"
	}
	if p.zero {
		name += ".Z"
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix[shape.destinationBytes], int(code[p.modRM]>>3&7)+p.r*8))})
	ins := Instr{Op: name, Args: args, x86Encoded: true, x86PackedNumericEVEX: p.evex}
	arch := "amd64"
	if mode == 32 {
		arch = "386"
	}
	shapeInput := ins
	if memory.physicalPC && source.Kind == OpMem && source.Mem.Base == "RIP" {
		// The physical decoder has already checked the complete disp32.
		// Check the conversion's memory class, not a Go source RIP spelling.
		// Return the original physical operand; only a boundary observer may
		// request this mode and it discards all decoded operands.
		shapeInput.Args = append([]Operand(nil), ins.Args...)
		shapeInput.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}}
	}
	_, _, err = x86PackedConversionProperties(shapeInput, arch)
	if err != nil {
		return Instr{}, 0, true, err
	}
	printed := make([]string, len(args))
	for index, operand := range args {
		printed[index] = operand.String()
	}
	ins.Raw = string(name) + " " + strings.Join(printed, ", ")
	return ins, p.modRM + consumed, true, nil
}
