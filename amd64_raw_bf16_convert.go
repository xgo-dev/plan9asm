package plan9asm

import (
	"fmt"
	"strings"
)

// Go 1.27 has no named AVX-512 BF16 encodings. Conversion and dot-product
// instructions share widths, masks and dword broadcasts; only conversion
// narrows its destination and reserves vvvv.
func decodedX86RawBF16Instruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || !p.evex || p.mapNumber != 2 || p.pp != 2 || (p.opcode != 0x72 && p.opcode != 0x52) {
		return Instr{}, 0, false, nil
	}
	dot := p.opcode == 0x52
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("raw BF16: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.w || !dot && p.upper != 0 || p.vectorLength > 2 {
		return fail("reserved EVEX width, source or vector-length field")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero K mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	registerSource := code[p.modRM]>>6 == 3
	if p.broadcast && registerSource {
		return fail("broadcast requires a memory source")
	}
	if mode == 32 && (!registerSource && (p.b != 0 || p.x != 0) || p.r != 0 || p.upper >= 8) {
		return fail("extended address or destination register in 32-bit mode")
	}

	sourceBytes := 16 << p.vectorLength
	sourcePrefix := [...]string{"X", "Y", "Z"}[p.vectorLength]
	destinationPrefix := [...]string{"X", "X", "Y"}[p.vectorLength]
	if dot {
		destinationPrefix = sourcePrefix
	}
	accessBytes := sourceBytes
	if p.broadcast {
		accessBytes = 4
	}
	source, consumed, err := decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix, accessBytes)
	if err != nil {
		return Instr{}, 0, true, err
	}
	if mode == 32 && registerSource {
		index, _ := amd64VectorRegisterIndex(source.Reg, sourceBytes)
		if index > 7 {
			return fail("extended source register in 32-bit mode")
		}
	}
	destination := int(code[p.modRM]>>3&7) + p.r*8
	op := [...]Op{"VCVTNEPS2BF16X", "VCVTNEPS2BF16Y", "VCVTNEPS2BF16"}[p.vectorLength]
	if dot {
		op = "VDPBF16PS"
	}
	if p.broadcast {
		op += ".BCST"
	}
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source}
	if dot {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", sourcePrefix, p.upper))})
	}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationPrefix, destination))})
	parts := make([]string, len(args))
	for i, arg := range args {
		parts[i] = arg.String()
	}
	return Instr{
		Op:         op,
		Args:       args,
		Raw:        fmt.Sprintf("%s %s", op, strings.Join(parts, ", ")),
		x86Encoded: true,
	}, p.modRM + consumed, true, nil
}

func decodeX86RawBF16RIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, ok := decodeX86RawVectorEncoding(code[offset:])
	if !ok || !p.evex || p.mapNumber != 2 || p.pp != 2 || (p.opcode != 0x52 && p.opcode != 0x72) ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRM := offset + p.modRM
	if len(code) <= modRM || code[modRM]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
	}
	return x86RawRIPDataThroughDecoder(code, offset, mode, modRM, width, decodedX86RawBF16Instruction, "BF16")
}
