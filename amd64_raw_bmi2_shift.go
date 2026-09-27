package plan9asm

import "fmt"

// All six Go _ybextrl forms use VEX.L0. Intel XED's hsw-bmi-vex-isa
// table leaves W unconstrained in not64 mode, so Q bytes decode as L on 386.
func decodedX86BMI2ShiftInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != 0xf7 || p.pp == 0 {
		return Instr{}, 0, false, nil
	}

	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("BMI2 variable shift: %s", message)
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

	bits := 32
	if p.w && mode == 64 {
		bits = 64
	}
	var op Op
	for name, spec := range amd64BMI2ShiftSpecs {
		if spec.bits == bits && spec.prefix == p.pp {
			op = Op(name)
			break
		}
	}

	source, size, err := decodedX86VEXRMSource(code[p.modRM:], mode, p.b, p.x, p.segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	count, _ := decodedX86GeneralRegister(p.upper)
	destination, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	instruction := Instr{
		Op: op,
		Args: []Operand{
			{Kind: OpReg, Reg: count},
			source,
			{Kind: OpReg, Reg: destination},
		},
		Raw: fmt.Sprintf("%s %s, %s, %s", op, count, source.String(), destination),
	}
	return instruction, p.modRM + size, true, nil
}
