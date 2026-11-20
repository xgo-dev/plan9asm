package plan9asm

import (
	"fmt"
	"strings"
)

var x86RawVectorHighLowMoveOps = map[int]Op{
	0x12: "VMOVHLPS",
	0x16: "VMOVLHPS",
}

// The Go 1.27 _yvmovhlps table has exactly two register-only 128-bit rows.
// ModRM memory encodings belong to the separate VMOVLPS/VMOVHPS family.
func decodedX86RawVectorHighLowMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.mapNumber != 1 || p.pp != 0 {
		return Instr{}, 0, false, nil
	}
	op, owned := x86RawVectorHighLowMoveOps[p.opcode]
	if !owned {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("vector high/low move: %s", message)
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if code[p.modRM]>>6 != 3 {
		return Instr{}, 0, false, nil
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.vectorLength != 0 || p.evex && (!p.fixed || p.w || p.mask != 0 || p.zero || p.broadcast) {
		return fail("invalid 128-bit VEX/EVEX register form")
	}
	if !p.evex && mode == 32 && (p.r != 0 || p.upper >= 8) {
		return fail("extended VEX register in 32-bit mode")
	}
	var first Operand
	var consumed int
	var err error
	if p.evex {
		first, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X", 16)
	} else {
		first, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	second := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", p.upper))}
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("X%d", destinationNumber))}
	args := []Operand{first, second, destination}
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
