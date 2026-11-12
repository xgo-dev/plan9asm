package plan9asm

import "fmt"

// Intel XED's AVX table specifies VL128, V66, V0F38 and NOVSR; W is ignored.
// There are no Y/Z, EVEX, mask, immediate or three-operand forms.
func decodedX86MinimumPositionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	spec := amd64MinimumPositionSpecs["VPHMINPOSUW"]
	if !matched || p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("minimum position: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.evex || p.vectorLength != 0 || p.pp != 1 || p.upper != 0 {
		return fail("requires VEX.128.66 with reserved vvvv")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if mode == 32 && (p.r != 0 || p.x != 0 || p.b != 0) {
		return fail("extended register in 32-bit mode")
	}
	source, size, err := decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, "X")
	if err != nil {
		return Instr{}, 0, true, err
	}
	dst := Reg(fmt.Sprintf("X%d", int(code[p.modRM]>>3&7)+p.r*8))
	return Instr{
		Op:   "VPHMINPOSUW",
		Args: []Operand{source, {Kind: OpReg, Reg: dst}},
		Raw:  fmt.Sprintf("VPHMINPOSUW %s, %s", source.String(), dst),
	}, p.modRM + size, true, nil
}
