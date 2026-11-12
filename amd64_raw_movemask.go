package plan9asm

import "fmt"

// Decode Go's VEX _yvmovmskpd family before x/arch can mistake opcode 50/D7
// for a legacy PUSH/XLATB. The source is always a vector register; ModRM.reg
// names the GP destination and vvvv is reserved.
func decodedX86VEXMoveMaskInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 1 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for name, spec := range amd64MoveMaskSpecs {
		if spec.vector && spec.opcode == p.opcode && spec.prefix == p.pp {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VEX move mask: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.upper != 0 || p.vectorLength > 1 {
		return fail("reserved vvvv or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 != 3 {
		return fail("source must be a vector register")
	}
	if mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	source := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]&7)+p.b*8))}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	destinationReg, valid := decodedX86GeneralRegister(destinationNumber)
	if !valid {
		return fail("invalid GP destination register")
	}
	destination := Operand{Kind: OpReg, Reg: destinationReg}
	return Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}, p.modRM + 1, true, nil
}
