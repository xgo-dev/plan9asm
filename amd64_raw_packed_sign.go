package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27's _yvaddsubpd table gives all three VPSIGN instructions exactly
// the same VEX.128/VEX.256 register-and-memory operand grammar.
var x86RawPackedSignOps = [...]Op{"VPSIGNB", "VPSIGNW", "VPSIGND"}

func decodedX86RawPackedSignInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode < 0x08 || p.opcode > 0x0a {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed sign: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.pp != 1 || p.w || p.addressOverride {
		return fail("Go's packed sign table only permits VEX.66.0F38.W0 without address override")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	width := [...]string{"X", "Y"}[p.vectorLength]
	destinationNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (destinationNumber >= 8 || p.upper >= 8) {
		return fail("extended vector register unavailable in 32-bit mode")
	}
	source, consumed, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, destinationNumber))}
	op := x86RawPackedSignOps[p.opcode-0x08]
	args := []Operand{source, data, destination}
	printed := []string{source.String(), data.String(), destination.String()}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
