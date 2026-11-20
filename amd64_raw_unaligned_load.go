package plan9asm

import "fmt"

func decodedX86VEXUnalignedLoadInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.opcode != 0xf0 || p.pp != 3 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VLDDQU: %s", message)
	}
	if mode != 32 && mode != 64 || p.evex || p.vectorLength > 1 || p.upper != 0 || p.addressOverride {
		return fail("invalid mode, VEX generation, length, reserved vvvv or address size")
	}
	if len(code) <= p.modRM || code[p.modRM]>>6 == 3 {
		return fail("missing or non-memory ModRM")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register unavailable in physical mode32")
	}
	bank := []string{"X", "Y"}[p.vectorLength]
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, bank)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if p.modRM+size > 15 {
		return fail("instruction exceeds 15 bytes")
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", bank, int(code[p.modRM]>>3&7)+p.r*8))}
	ins := Instr{Op: "VLDDQU", Args: []Operand{source, destination}, x86Encoded: true}
	ins.Raw = fmt.Sprintf("VLDDQU %s,%s", source.String(), destination.String())
	return ins, p.modRM + size, true, nil
}
