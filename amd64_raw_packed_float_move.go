package plan9asm

import (
	"fmt"
	"strings"
)

// Go's packed move grammars share width, direction and memory axes. The pinned
// generic decoder can misread VEX moves as legacy instructions or lose their
// vector width, so decode the complete float and VEX integer families here.
func decodedX86PackedMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	store := false
	switch p.opcode {
	case 0x28, 0x29:
		if p.pp > 1 {
			return Instr{}, 0, false, nil
		}
		op = Op("VMOVA" + []string{"PS", "PD"}[p.pp])
		store = p.opcode == 0x29
	case 0x10, 0x11:
		if p.pp > 1 {
			return Instr{}, 0, false, nil
		}
		op = Op("VMOVU" + []string{"PS", "PD"}[p.pp])
		store = p.opcode == 0x11
	case 0x6f, 0x7f:
		if p.evex || (p.pp != 1 && p.pp != 2) {
			return Instr{}, 0, false, nil
		}
		op = Op([]string{"", "VMOVDQA", "VMOVDQU"}[p.pp])
		store = p.opcode == 0x7f
	default:
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed float move: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.upper != 0 {
		return fail("vvvv and V' must be reserved")
	}
	if p.evex && (!p.fixed || p.w != (p.pp == 1)) {
		return fail("invalid EVEX fixed or width bit")
	}
	if p.vectorLength > 2 || p.broadcast {
		return fail("reserved vector length or broadcast bit")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	registerForm := code[p.modRM]>>6 == 3
	if p.zero && (p.mask == 0 || store && !registerForm) {
		return fail("zeroing requires a nonzero mask and register destination")
	}
	width := []string{"X", "Y", "Z"}[p.vectorLength]
	regNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && ((!p.evex || width == "Z") && regNumber >= 8) {
		return fail("extended register unavailable in 32-bit mode")
	}
	reg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, regNumber))}
	var rm Operand
	var consumed int
	var err error
	if p.evex {
		rm, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width, 16<<p.vectorLength)
	} else {
		rm, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	args := []Operand{rm, reg}
	if store {
		args[0], args[1] = reg, rm
	}
	if p.mask != 0 {
		args = []Operand{args[0], {Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}, args[1]}
	}
	if p.zero {
		op += ".Z"
	}
	printed := make([]string, len(args))
	for i := range args {
		printed[i] = args[i].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
