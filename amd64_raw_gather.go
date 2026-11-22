package plan9asm

import (
	"fmt"
	"strings"
)

// The eight data-gather spellings share the same opcode axes in Go's
// _yvgatherdps, _yvgatherdpd and _yvgatherqps tables. The ModRM/SIB operand
// is VSIB memory: its index is a vector register, never a GP register.
var x86GatherOps = [4][2]Op{
	{"VPGATHERDD", "VPGATHERDQ"},
	{"VPGATHERQD", "VPGATHERQQ"},
	{"VGATHERDPS", "VGATHERDPD"},
	{"VGATHERQPS", "VGATHERQPD"},
}

// The four packed and four floating-point scatter spellings mirror the EVEX
// gather VSIB axes, but encode the data vector in ModRM.reg and store to VSIB.
var x86ScatterOps = [4][2]Op{
	{"VPSCATTERDD", "VPSCATTERDQ"},
	{"VPSCATTERQD", "VPSCATTERQQ"},
	{"VSCATTERDPS", "VSCATTERDPD"},
	{"VSCATTERQPS", "VSCATTERQPD"},
}

func decodedX86VSIBData(code []byte, mode int, p x86RawVectorEncoding, scatter bool) (Instr, int, bool, error) {
	w := 0
	if p.w {
		w = 1
	}
	var op Op
	var spec amd64GatherSpec
	if scatter {
		op = x86ScatterOps[p.opcode-0xa0][w]
		spec = amd64ScatterSpecs[string(op)]
	} else {
		op = x86GatherOps[p.opcode-0x90][w]
		spec = amd64GatherSpecs[op]
	}
	if err := validateX86VSIBEncoding(code, mode, p); err != nil {
		return Instr{}, 0, true, fmt.Errorf("%s: %w", op, err)
	}
	dataBytes, indexBytes := x86VSIBWidths(spec.table, p.vectorLength)
	dataNumber := int(code[p.modRM]>>3&7) + p.r*8
	if mode == 32 && (!p.evex && (dataNumber >= 8 || p.upper >= 8) ||
		p.evex && dataBytes == 64 && dataNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("%s: extended data or mask register unavailable in 32-bit mode", op)
	}

	memory, consumed, err := decodedX86VSIBMemory(code, mode, p, indexBytes, spec.elemBits/8)
	if err != nil {
		return Instr{}, 0, true, fmt.Errorf("%s: %w", op, err)
	}
	data := x86VSIBVectorOperand(dataBytes, dataNumber)
	var args []Operand
	switch {
	case scatter:
		args = []Operand{data, x86VSIBMaskOperand(p), memory}
	case p.evex:
		args = []Operand{memory, x86VSIBMaskOperand(p), data}
	default:
		args = []Operand{x86VSIBVectorOperand(dataBytes, p.upper), memory, data}
	}
	return decodedX86VSIBInstruction(op, args), p.modRM + consumed, true, nil
}

func validateX86VSIBEncoding(code []byte, mode int, p x86RawVectorEncoding) error {
	if mode != 32 && mode != 64 {
		return fmt.Errorf("unsupported x86 mode")
	}
	if p.addressOverride {
		return fmt.Errorf("address-size override is not source-layout safe")
	}
	if p.evex && (!p.fixed || p.vectorLength > 2 || p.mask == 0 || p.zero || p.broadcast || p.upper&15 != 0) {
		return fmt.Errorf("invalid EVEX fixed, length, mask, zeroing, broadcast or vvvv bits")
	}
	if len(code) < p.modRM+2 {
		return fmt.Errorf("missing ModRM or VSIB byte")
	}
	if modRM := code[p.modRM]; modRM>>6 == 3 || modRM&7 != 4 {
		return fmt.Errorf("expected VSIB memory")
	}
	return nil
}

func decodedX86VSIBMemory(code []byte, mode int, p x86RawVectorEncoding, indexBytes, elemBytes int) (Operand, int, error) {
	sib := code[p.modRM+1]
	indexNumber := int(sib>>3&7) + p.x*8
	disp8Scale := 1
	if p.evex {
		indexNumber += p.upper & 16
		disp8Scale = elemBytes
	}
	if mode == 32 && (indexNumber >= 8 || p.b != 0) {
		return Operand{}, 0, fmt.Errorf("extended VSIB address register unavailable in 32-bit mode")
	}
	memory, consumed, err := decodedX86RMSource(code[p.modRM:], mode, p.b, 0, p.segment, disp8Scale)
	if err != nil {
		return Operand{}, 0, err
	}
	memory.Mem.Index = x86VSIBVectorOperand(indexBytes, indexNumber).Reg
	memory.Mem.Scale = int64(1 << (sib >> 6))
	return memory, consumed, nil
}

func x86VSIBVectorOperand(width, number int) Operand {
	bank := 'X'
	switch width {
	case 32:
		bank = 'Y'
	case 64:
		bank = 'Z'
	}
	return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%c%d", bank, number))}
}

func x86VSIBMaskOperand(p x86RawVectorEncoding) Operand {
	return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}
}

func decodedX86VSIBInstruction(op Op, args []Operand) Instr {
	printed := make([]string, len(args))
	for i, arg := range args {
		printed[i] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}
}

// The raw and whole-source boundary consumers share this encoding grammar.
// A prefetch hint uses ModRM.reg as an opcode extension and the same address
// transport as the gather and scatter data instructions.
func decodedX86RawVSIBInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	switch {
	case p.opcode >= 0x90 && p.opcode <= 0x93:
		return decodedX86VSIBData(code, mode, p, false)
	case p.evex && p.opcode >= 0xa0 && p.opcode <= 0xa3:
		return decodedX86VSIBData(code, mode, p, true)
	case p.evex && (p.opcode == 0xc6 || p.opcode == 0xc7):
		return decodedX86VSIBPrefetch(code, mode, p)
	}
	return Instr{}, 0, false, nil
}

func decodedX86VSIBPrefetch(code []byte, mode int, p x86RawVectorEncoding) (Instr, int, bool, error) {
	if err := validateX86VSIBEncoding(code, mode, p); err != nil {
		return Instr{}, 0, true, fmt.Errorf("VSIB prefetch: %w", err)
	}
	if p.vectorLength != 2 || p.r != 0 {
		return Instr{}, 0, true, fmt.Errorf("invalid VSIB prefetch length or opcode extension")
	}
	extension := int(code[p.modRM] >> 3 & 7)
	direction := "VGATHER"
	if extension >= 5 {
		extension -= 4
		direction = "VSCATTER"
	}
	if extension != 1 && extension != 2 {
		return Instr{}, 0, true, fmt.Errorf("invalid VSIB prefetch opcode extension")
	}
	indexKind := "D"
	if p.opcode == 0xc7 {
		indexKind = "Q"
	}
	elemKind := "S"
	if p.w {
		elemKind = "D"
	}
	op := Op(fmt.Sprintf("%sPF%d%sP%s", direction, extension-1, indexKind, elemKind))
	spec := amd64VSIBPrefetchSpecs[op]
	memory, consumed, err := decodedX86VSIBMemory(code, mode, p, spec.indexBytes, spec.elemBits/8)
	if err != nil {
		return Instr{}, 0, true, fmt.Errorf("%s: %w", op, err)
	}
	return decodedX86VSIBInstruction(op, []Operand{x86VSIBMaskOperand(p), memory}), p.modRM + consumed, true, nil
}
