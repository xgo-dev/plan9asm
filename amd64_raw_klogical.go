package plan9asm

import "fmt"

// decodedX86RawKLogicalInstruction models Go 1.27's _ykaddb and _yknotb
// mask-register tables as opcode, width prefix, and K-operand arity. It
// includes KADD, KAND/ANDN, KOR, KXNOR/XOR, KUNPCK, KNOT, KTEST and KORTEST.
func decodedX86RawKLogicalInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	stem, arity := x86RawKLogicalOpcode(p.opcode)
	if stem == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("K-register operation: %s", message)
	}
	if p.pp > 1 {
		return fail("reserved VEX.pp")
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride || p.segment != "" || p.r != 0 || p.b != 0 || p.x != 0 {
		return fail("invalid address or register extension prefix")
	}
	length := 0
	if arity == 3 {
		length = 1
	}
	if p.vectorLength != length || p.upper >= 8 || arity == 2 && p.upper != 0 {
		return fail("invalid VEX length or vvvv K register")
	}
	op, ok := x86RawKLogicalOperation(stem, p.pp, p.w)
	if !ok {
		return fail("reserved width or opcode combination")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	modRM := code[p.modRM]
	if modRM>>6 != 3 {
		return fail("K-register operation requires register operands")
	}
	source1 := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", modRM&7))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", modRM>>3&7))}
	args := []Operand{source1}
	if arity == 3 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.upper))})
	}
	args = append(args, destination)
	raw := fmt.Sprintf("%s %s, %s", op, source1.String(), destination.String())
	if arity == 3 {
		raw = fmt.Sprintf("%s %s, %s, %s", op, source1.String(), args[1].String(), destination.String())
	}
	return Instr{Op: op, Args: args, Raw: raw}, p.modRM + 1, true, nil
}

func x86RawKLogicalOpcode(opcode int) (stem string, arity int) {
	switch opcode {
	case 0x4a:
		return "KADD", 3
	case 0x41:
		return "KAND", 3
	case 0x42:
		return "KANDN", 3
	case 0x45:
		return "KOR", 3
	case 0x46:
		return "KXNOR", 3
	case 0x47:
		return "KXOR", 3
	case 0x4b:
		return "KUNPCK", 3
	case 0x44:
		return "KNOT", 2
	case 0x98:
		return "KORTEST", 2
	case 0x99:
		return "KTEST", 2
	}
	return "", 0
}

func x86RawKLogicalOperation(stem string, pp int, w bool) (Op, bool) {
	if stem == "KUNPCK" {
		switch {
		case pp == 1 && !w:
			return "KUNPCKBW", true
		case pp == 0 && !w:
			return "KUNPCKWD", true
		case pp == 0 && w:
			return "KUNPCKDQ", true
		}
		return "", false
	}
	suffix := "W"
	if pp == 1 {
		suffix = "B"
	}
	if w {
		suffix = "Q"
		if pp == 1 {
			suffix = "D"
		}
	}
	return Op(stem + suffix), true
}
