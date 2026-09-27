package plan9asm

import "fmt"

// Go's four _yvcomisd entries share X/m,X and EVEX register-only SAE.
// Prefix fields stay typed: EVEX.b means SAE here, never memory broadcast;
// disp8 scales by the scalar width. VEX W/L and EVEX LL are ignored by
// this scalar family (Intel XED datafiles/avx/avx-isa.txt and AVX512 tables).
func decodedX86ScalarFlagCompareInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || (p.opcode != 0x2e && p.opcode != 0x2f) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("scalar flag compare: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if (p.pp != 0 && p.pp != 1) || p.upper != 0 || p.mask != 0 || p.zero {
		return fail("reserved prefix, vvvv/V', mask or zeroing field")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	double := p.pp == 1
	if p.evex && (!p.fixed || p.w != double) {
		return fail("invalid EVEX fixed or scalar width bit")
	}
	if p.broadcast && code[p.modRM]>>6 != 3 {
		return fail("SAE requires a register source")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	op := Op("VCOMISS")
	if p.opcode == 0x2e {
		op = "VUCOMISS"
	}
	bytes := 4
	if double {
		op = op[:len(op)-1] + "D"
		bytes = 8
	}
	if p.broadcast {
		op += ".SAE"
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
	dst := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{Op: op, Args: []Operand{source, dst}, Raw: fmt.Sprintf("%s %s, %s", op, source.String(), dst.String())}, p.modRM + size, true, nil
}
