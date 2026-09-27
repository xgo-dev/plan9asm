package plan9asm

import "fmt"

// Go's _yvbroadcastss/_yvbroadcastsd tables share the typed VEX/EVEX
// prefix grammar. The scalar input width, output width and mask are separate
// axes: SD has no 128-bit destination, and disp8 scales by scalar input size.
func decodedX86ScalarBroadcastInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || (p.opcode != 0x18 && p.opcode != 0x19) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar broadcast: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.upper != 0 || p.broadcast {
		return fail("reserved prefix, vvvv/V' or broadcast field")
	}
	double := p.opcode == 0x19
	if p.vectorLength > 2 || double && p.vectorLength == 0 {
		return fail("invalid vector width")
	}
	if p.evex {
		if !p.fixed || p.w != double {
			return fail("invalid EVEX fixed or width bit")
		}
	} else if p.w {
		return fail("VEX.W must be zero")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	op, bytes := Op("VBROADCASTSS"), 4
	if double {
		op, bytes = "VBROADCASTSD", 8
	}
	var source Operand
	var size int
	var err error
	if p.evex {
		source, size, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", bytes)
	} else {
		source, size, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	reg := int(code[p.modRM]>>3&7) + p.r*8
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", []string{"X", "Y", "Z"}[p.vectorLength], reg))}
	args := []Operand{source, destination}
	printed := source.String() + ", " + destination.String()
	if p.mask != 0 {
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}
		args = []Operand{source, mask, destination}
		printed = source.String() + ", " + mask.String() + ", " + destination.String()
	}
	if p.zero {
		op += ".Z"
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, printed)}, p.modRM + size, true, nil
}
