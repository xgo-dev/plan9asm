package plan9asm

import "fmt"

// decodedX86RawBZHIInstruction follows Go's two _ybextrl rows, BZHIL/Q.
// Both use VEX.128.0F38.W{0,1} F5 /r with a register index, register or
// memory source, and register destination. In 32-bit mode W is ignored.
func decodedX86RawBZHIInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != 0xf5 || p.pp != 0 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("BZHI: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 {
		return fail("requires VEX.L0 encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	op := Op("BZHIL")
	if p.w && mode == 64 {
		op = "BZHIQ"
	}
	source, size, err := decodedX86VEXRMSource(code[p.modRM:], mode, p.b, p.x, p.segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	index, _ := decodedX86GeneralRegister(p.upper)
	destination, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	return Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: index}, source, {Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, index, source.String(), destination),
	}, p.modRM + size, true, nil
}
