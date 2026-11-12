package plan9asm

import "fmt"

// Intel RCPSS/RSQRTSS share legacy F3.0F and VEX.LIG.F3.0F.WIG
// register/m32 rows. Ignored W/L bits do not widen the selected scalar or
// change the upper source. EVEX belongs to other estimate families.
func decodedX86RawScalarReciprocalInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, vector := decodeX86RawVectorEncoding(code)
	if vector {
		if p.mapNumber != 1 || p.pp != 2 || p.opcode != 0x52 && p.opcode != 0x53 {
			return Instr{}, 0, false, nil
		}
	} else {
		i := 0
		mandatory := false
		for i < len(code) {
			switch code[i] {
			case 0x64:
				p.segment = FS
			case 0x65:
				p.segment = GS
			case 0x67:
				p.addressOverride = true
			case 0xf3:
				mandatory = true
			default:
				goto legacy
			}
			i++
		}
	legacy:
		rex := byte(0)
		if i < len(code) && code[i]&0xf0 == 0x40 {
			rex = code[i]
			i++
		}
		if !mandatory || len(code) < i+2 || code[i] != 0x0f || code[i+1] != 0x52 && code[i+1] != 0x53 {
			return Instr{}, 0, false, nil
		}
		p.opcode, p.modRM = int(code[i+1]), i+2
		p.r, p.x, p.b = int(rex>>2&1), int(rex>>1&1), int(rex&1)
		if mode == 32 && rex != 0 {
			return Instr{}, 0, true, fmt.Errorf("scalar reciprocal: REX unavailable in 32-bit mode")
		}
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar reciprocal: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.addressOverride {
		return fail("EVEX or address-size override has no scalar estimate source contract")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0 || p.upper >= 8) {
		return fail("extended physical register in 32-bit mode")
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))}
	op := Op("RCPSS")
	if p.opcode == 0x52 {
		op = "RSQRTSS"
	}
	args := []Operand{source, destination}
	printed := source.String() + ", " + destination.String()
	if vector {
		op = "V" + op
		base := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
		args = []Operand{source, base, destination}
		printed = source.String() + ", " + base.String() + ", " + destination.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, printed)}, p.modRM + consumed, true, nil
}
