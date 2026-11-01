package plan9asm

import (
	"fmt"
	"strings"
)

type x86LegacyMMXTable uint8

const (
	x86LegacyMMXBinary x86LegacyMMXTable = iota
	x86LegacyMMXHorizontal
	x86LegacyMMXShuffle
	x86LegacyMMXCount
)

type x86LegacyMMXReadSpec struct {
	table                                x86LegacyMMXTable
	opcode, immediateOpcode, opcodeDigit byte
}

// This is the complete integer MMX-read class in Go's ymm, ymmxmm0f38,
// ymshuf and yps tables. MOVQ, PINSR, PEXTR and floating conversions have
// different ordered operand roles and must not use this bank selector.
var x86LegacyMMXReadSpecs = map[Op]x86LegacyMMXReadSpec{
	"PACKSSLW":  {opcode: 0x6b},
	"PACKSSWB":  {opcode: 0x63},
	"PACKUSWB":  {opcode: 0x67},
	"PADDB":     {opcode: 0xfc},
	"PADDL":     {opcode: 0xfe},
	"PADDW":     {opcode: 0xfd},
	"PADDSB":    {opcode: 0xec},
	"PADDSW":    {opcode: 0xed},
	"PADDUSB":   {opcode: 0xdc},
	"PADDUSW":   {opcode: 0xdd},
	"PAND":      {opcode: 0xdb},
	"PANDN":     {opcode: 0xdf},
	"POR":       {opcode: 0xeb},
	"PXOR":      {opcode: 0xef},
	"PAVGB":     {opcode: 0xe0},
	"PAVGW":     {opcode: 0xe3},
	"PCMPEQB":   {opcode: 0x74},
	"PCMPEQW":   {opcode: 0x75},
	"PCMPEQL":   {opcode: 0x76},
	"PCMPGTB":   {opcode: 0x64},
	"PCMPGTW":   {opcode: 0x65},
	"PCMPGTL":   {opcode: 0x66},
	"PMADDWL":   {opcode: 0xf5},
	"PMULLW":    {opcode: 0xd5},
	"PMULHW":    {opcode: 0xe5},
	"PMULHUW":   {opcode: 0xe4},
	"PMULULQ":   {opcode: 0xf4},
	"PUNPCKHBW": {opcode: 0x68},
	"PUNPCKHWL": {opcode: 0x69},
	"PUNPCKHLQ": {opcode: 0x6a},
	"PUNPCKLBW": {opcode: 0x60},
	"PUNPCKLWL": {opcode: 0x61},
	"PUNPCKLLQ": {opcode: 0x62},
	"PHADDD":    {table: x86LegacyMMXHorizontal, opcode: 0x02},
	"PSHUFW":    {table: x86LegacyMMXShuffle, opcode: 0x70},
	"PSLLW":     {x86LegacyMMXCount, 0xf1, 0x71, 6},
	"PSLLL":     {x86LegacyMMXCount, 0xf2, 0x72, 6},
	"PSLLQ":     {x86LegacyMMXCount, 0xf3, 0x73, 6},
	"PSRLW":     {x86LegacyMMXCount, 0xd1, 0x71, 2},
	"PSRLL":     {x86LegacyMMXCount, 0xd2, 0x72, 2},
	"PSRLQ":     {x86LegacyMMXCount, 0xd3, 0x73, 2},
	"PSRAW":     {x86LegacyMMXCount, 0xe1, 0x71, 4},
	"PSRAL":     {x86LegacyMMXCount, 0xe2, 0x72, 4},
}

type x86LegacyMMXEncodingRow struct {
	classes             []string
	zcase               string
	zoffset, byteOffset int
}

func (s x86LegacyMMXReadSpec) encoderRows() (string, string, []byte, []x86LegacyMMXEncodingRow) {
	switch s.table {
	case x86LegacyMMXBinary:
		return "ymm", "Py1", []byte{s.opcode, 0x66, s.opcode}, []x86LegacyMMXEncodingRow{
			{[]string{"Ymm", "Ymr"}, "Zm_r_xm", 1, 0},
			{[]string{"Yxm", "Yxr"}, "Zm_r_xm", 2, 1},
		}
	case x86LegacyMMXHorizontal:
		// Go advances z by zoffset+xo; the initial 0x0f makes xo=1.
		return "ymmxmm0f38", "Px", []byte{0x0f, 0x38, s.opcode, 0, 0x66, 0x0f, 0x38, s.opcode, 0}, []x86LegacyMMXEncodingRow{
			{[]string{"Ymm", "Ymr"}, "Zlitm_r", 3, 0},
			{[]string{"Yxm", "Yxr"}, "Zlitm_r", 5, 4},
		}
	case x86LegacyMMXShuffle:
		return "ymshuf", "Pm", []byte{s.opcode, 0}, []x86LegacyMMXEncodingRow{
			{[]string{"Yi8", "Ymm", "Ymr"}, "Zibm_r", 2, 0},
		}
	default:
		return "yps", "Py3", []byte{s.opcode, s.immediateOpcode, s.opcodeDigit,
			0x66, s.opcode, 0x66, s.immediateOpcode, s.opcodeDigit}, []x86LegacyMMXEncodingRow{
			{[]string{"Ymm", "Ymr"}, "Zm_r_xm", 1, 0},
			{[]string{"Yi8", "Ymr"}, "Zibo_m_xm", 2, 1},
			{[]string{"Yxm", "Yxr"}, "Zm_r_xm", 2, 3},
			{[]string{"Yi8", "Yxr"}, "Zibo_m_xm", 3, 5},
		}
	}
}

type x86LegacyMMXReadForm struct {
	canonical                Op
	spec                     x86LegacyMMXReadSpec
	row                      int
	sourceIndex, destination int
	source                   Operand
	byteWidth, memoryBytes   int
	mmx, gpSpelling          bool
}

func x86LegacyMMXGPBank(reg Reg, arch string) (Reg, bool) {
	for index, register := range [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI,
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		if reg == register && (arch == "amd64" || arch == "386" && index < 8) {
			return Reg(fmt.Sprintf("M%d", index&7)), true
		}
	}
	return "", false
}

// The selected Go row records physical source identity only. It does not
// define any M register, authorize a native address, model x87 state or
// supply an incoming/caller contract. Raw physical instructions never turn
// a GP source into MMX through Go's source-only ycover compatibility.
func x86LegacyMMXReadProperties(ins Instr, arch string) (x86LegacyMMXReadForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if name == "PADDD" {
		name = "PADDL"
	}
	spec, known := x86LegacyMMXReadSpecs[Op(name)]
	if !known {
		return x86LegacyMMXReadForm{}, false, nil
	}
	form := x86LegacyMMXReadForm{canonical: Op(name), spec: spec, sourceIndex: 0,
		destination: len(ins.Args) - 1, byteWidth: 16}
	fail := func() (x86LegacyMMXReadForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go integer Ymm read rows: %q", arch, ins.Op, ins.Raw)
	}
	want := 2
	if spec.table == x86LegacyMMXShuffle {
		want, form.sourceIndex = 3, 1
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != want || ins.Args[form.destination].Kind != OpReg {
		return fail()
	}
	destination := ins.Args[form.destination]
	_, form.mmx = amd64ParseMReg(destination.Reg)
	if form.mmx {
		form.byteWidth = 8
		if arch == "386" && !ins.x86Encoded && (spec.table == x86LegacyMMXBinary || spec.table == x86LegacyMMXCount) {
			return fail()
		}
	} else {
		index, valid := amd64ParseXReg(destination.Reg)
		if !valid || index >= 16 || arch == "386" && index >= 8 || spec.table == x86LegacyMMXShuffle {
			return fail()
		}
	}
	form.source = ins.Args[form.sourceIndex]
	immediate := spec.table == x86LegacyMMXCount && form.source.Kind == OpImm
	if spec.table == x86LegacyMMXShuffle || immediate {
		operand, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
		if !integer || !amd64SignedImmediate(operand, 8) {
			return fail()
		}
	}
	switch {
	case immediate:
		// An immediate count has no source-bank read.
	case form.source.Kind == OpReg && form.mmx:
		if _, valid := amd64ParseMReg(form.source.Reg); !valid {
			register, valid := x86LegacyMMXGPBank(form.source.Reg, arch)
			if !valid || ins.x86Encoded {
				return fail()
			}
			form.source.Reg, form.gpSpelling = register, true
		}
	case form.source.Kind == OpReg:
		index, valid := amd64ParseXReg(form.source.Reg)
		if !valid || index >= 16 || arch == "386" && index >= 8 {
			return fail()
		}
	case isAMD64MemoryOperand(form.source) && x86PackedShiftMemoryValid(form.source, arch):
		form.memoryBytes = form.byteWidth
		if form.mmx && (name == "PUNPCKLBW" || name == "PUNPCKLWL" || name == "PUNPCKLLQ") {
			form.memoryBytes = 4
		}
	default:
		return fail()
	}
	if spec.table == x86LegacyMMXCount {
		if form.mmx {
			if immediate {
				form.row = 1
			}
		} else {
			form.row = 2
			if immediate {
				form.row = 3
			}
		}
	} else if !form.mmx {
		form.row = 1
	}
	return form, true, nil
}

func x86LegacyMMXReadInstruction(ins Instr, arch string) (Instr, error) {
	form, known, err := x86LegacyMMXReadProperties(ins, arch)
	if !known || err != nil {
		return ins, err
	}
	local := ins
	local.Args = append([]Operand(nil), ins.Args...)
	local.Args[form.sourceIndex] = form.source
	return local, nil
}

func x86LegacyMMXReadEmitterContext(ins Instr, arch string) error {
	form, known, err := x86LegacyMMXReadProperties(ins, arch)
	if !known || err != nil {
		return err
	}
	if form.gpSpelling {
		return fmt.Errorf("%w: %s source %s encodes %s without a proved initialized physical MMX bank transport",
			ErrProbeNeedsContext, ins.Op, ins.Args[form.sourceIndex].Reg, form.source.Reg)
	}
	return nil
}
