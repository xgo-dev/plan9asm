package plan9asm

import "fmt"

// Go's VPHADD/PHSUB family has two _yvaddsubpd rows, X and Y, without
// EVEX/masks. W is ignored (Go emits W0); Intel XED leaves W unconstrained:
// https://github.com/intelxed/xed/blob/main/datafiles/avx/avx-isa.txt
func decodedX86VEXHorizontalIntegerInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for name, spec := range amd64HorizontalIntegerSpecs {
		if spec.vector && int(spec.opcode) == p.opcode {
			op = name
			break
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("horizontal integer: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.pp != 1 || p.vectorLength > 1 {
		return fail("requires VEX.66.0F38 X/Y encoding")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0 || p.upper >= 8) {
		return fail("extended register in 32-bit mode")
	}
	width := []string{"X", "Y"}[p.vectorLength]
	source2, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, width)
	if err != nil {
		return Instr{}, 0, true, err
	}
	source1 := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, p.upper))}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", width, int(code[p.modRM]>>3&7)+p.r*8))}
	return Instr{
		Op: op, Args: []Operand{source2, source1, destination},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, source2.String(), source1.String(), destination.String()),
	}, p.modRM + size, true, nil
}
