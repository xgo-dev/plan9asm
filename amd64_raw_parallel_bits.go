package plan9asm

import "fmt"

// PDEP/PEXT share Go's _yandnl register/memory-mask grammar. Intel XED's
// datafiles/hswbmi/hsw-bmi-vex-isa.xed.txt confirms W is ignored in not64
// mode, while L must be zero. This is BMI2, not an arbitrary AVX fallback.
func decodedX86ParallelBitsInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 2 || p.opcode != 0xf5 || (p.pp != 2 && p.pp != 3) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("parallel bit operation: %s", message)
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
	for name, spec := range amd64ParallelBitSpecs {
		if spec.bits == bits && spec.prefix == p.pp {
			op = Op(name)
			break
		}
	}
	mask, size, err := decodedX86VEXRMSource(code[p.modRM:], mode, p.b, p.x, p.segment)
	if err != nil {
		return Instr{}, 0, true, err
	}
	src, _ := decodedX86GeneralRegister(p.upper)
	dst, _ := decodedX86GeneralRegister(int(code[p.modRM]>>3&7) + p.r*8)
	return Instr{Op: op, Args: []Operand{mask, {Kind: OpReg, Reg: src}, {Kind: OpReg, Reg: dst}}, Raw: fmt.Sprintf("%s %s, %s, %s", op, mask.String(), src, dst)}, p.modRM + size, true, nil
}
