package plan9asm

import "fmt"

// Go's _yvptest table has the same X/m128,X and Y/m256,Y grammar for all
// three VEX vector-test instructions. Legacy PTEST uses the same two-operand
// shape but is decoded by x/arch's existing SSE path.
var x86RawVectorTestOpcodes = map[int]Op{
	0x17: "VPTEST",
	0x0e: "VTESTPS",
	0x0f: "VTESTPD",
}

func decodedX86VEXVectorTestInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.evex || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	op, recognized := x86RawVectorTestOpcodes[p.opcode]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("VEX vector test: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.pp != 1 || p.upper != 0 || p.vectorLength > 1 {
		return fail("invalid 66 prefix, reserved vvvv or vector length")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
		return fail("extended register in 32-bit mode")
	}
	width := "X"
	if p.vectorLength == 1 {
		width = "Y"
	}
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{
		Op:   op,
		Args: []Operand{source, destination},
		Raw:  fmt.Sprintf("%s %s, %s", op, source.String(), destination.String()),
	}, p.modRM + size, true, nil
}
