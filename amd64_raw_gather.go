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

func decodedX86RawScatterInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || !p.evex || p.mapNumber != 2 || p.pp != 1 ||
		p.opcode < 0xa0 || p.opcode > 0xa3 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("raw scatter: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if !p.fixed || p.vectorLength > 2 || p.mask == 0 || p.zero ||
		p.broadcast || p.upper&15 != 0 {
		return fail("invalid EVEX fixed, length, mask, zeroing, broadcast or vvvv bits")
	}
	if len(code) < p.modRM+2 {
		return fail("missing ModRM or VSIB byte")
	}
	modRM := code[p.modRM]
	if modRM>>6 == 3 || modRM&7 != 4 {
		return fail("scatter requires VSIB memory")
	}
	w := 0
	if p.w {
		w = 1
	}
	op := x86ScatterOps[p.opcode-0xa0][w]
	spec := amd64ScatterSpecs[string(op)]
	widths := [...]string{"X", "Y", "Z"}
	dataWidth := widths[p.vectorLength]
	indexWidth := dataWidth
	switch spec.table {
	case amd64GatherDPD:
		if p.vectorLength > 0 {
			indexWidth = widths[p.vectorLength-1]
		}
	case amd64GatherQPS:
		if p.vectorLength > 0 {
			dataWidth = widths[p.vectorLength-1]
		}
	}
	dataNumber := int(modRM>>3&7) + p.r*8
	indexNumber := int(code[p.modRM+1]>>3&7) + p.x*8 + p.upper&16
	if mode == 32 && (indexNumber >= 8 || p.b != 0 ||
		dataWidth == "Z" && dataNumber >= 8) {
		return fail("extended register unavailable in 32-bit mode")
	}
	memory, consumed, err := decodedX86RMSource(
		code[p.modRM:], mode, p.b, p.x, p.segment, spec.elemBits/8,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	memory.Mem.Index = Reg(fmt.Sprintf("%s%d", indexWidth, indexNumber))
	memory.Mem.Scale = int64(1 << (code[p.modRM+1] >> 6))
	data := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", dataWidth, dataNumber))}
	mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}
	args := []Operand{data, mask, memory}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s, %s, %s", op, data.String(), mask.String(), memory.String()),
	}, p.modRM + consumed, true, nil
}

func decodedX86RawGatherInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, ok := decodeX86RawVectorEncoding(code)
	if !ok || p.mapNumber != 2 || p.pp != 1 || p.opcode < 0x90 || p.opcode > 0x93 {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("raw gather: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.evex && (!p.fixed || p.vectorLength > 2 || p.mask == 0 || p.zero || p.broadcast || p.upper&15 != 0) {
		return fail("invalid EVEX fixed, length, mask, zeroing, broadcast or vvvv bits")
	}
	if len(code) < p.modRM+2 {
		return fail("missing ModRM or VSIB byte")
	}
	modRM := code[p.modRM]
	if modRM>>6 == 3 || modRM&7 != 4 {
		return fail("gather requires VSIB memory")
	}

	w := 0
	if p.w {
		w = 1
	}
	op := x86GatherOps[p.opcode-0x90][w]
	spec := amd64GatherSpecs[op]
	widths := [...]string{"X", "Y", "Z"}
	destinationWidth := widths[p.vectorLength]
	indexWidth := destinationWidth
	switch spec.table {
	case amd64GatherDPD:
		if p.vectorLength > 0 {
			indexWidth = widths[p.vectorLength-1]
		}
	case amd64GatherQPS:
		if p.vectorLength > 0 {
			destinationWidth = widths[p.vectorLength-1]
		}
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	indexNumber := int(code[p.modRM+1]>>3&7) + p.x*8
	if p.evex {
		indexNumber += p.upper & 16
	}
	if mode == 32 && (indexNumber >= 8 || p.b != 0 ||
		!p.evex && (destinationNumber >= 8 || p.upper >= 8) ||
		p.evex && destinationWidth == "Z" && destinationNumber >= 8) {
		return fail("extended register unavailable in 32-bit mode")
	}

	disp8Scale := 1
	if p.evex {
		disp8Scale = spec.elemBits / 8
	}
	memory, consumed, err := decodedX86RMSource(code[p.modRM:], mode, p.b, p.x, p.segment, disp8Scale)
	if err != nil {
		return Instr{}, 0, true, err
	}
	memory.Mem.Index = Reg(fmt.Sprintf("%s%d", indexWidth, indexNumber))
	memory.Mem.Scale = int64(1 << (code[p.modRM+1] >> 6))
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationWidth, destinationNumber))}
	var args []Operand
	if p.evex {
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))}
		args = []Operand{memory, mask, destination}
	} else {
		mask := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationWidth, p.upper))}
		args = []Operand{mask, memory, destination}
	}
	printed := make([]string, len(args))
	for i, arg := range args {
		printed[i] = arg.String()
	}
	return Instr{
		Op:   op,
		Args: args,
		Raw:  fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
	}, p.modRM + consumed, true, nil
}
