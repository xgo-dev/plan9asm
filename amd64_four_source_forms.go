package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FourSourceMode uint8

const (
	amd64FourSourceFMA amd64FourSourceMode = iota
	amd64FourSourceDotWords
)

type amd64FourSourceSpec struct {
	mode       amd64FourSourceMode
	scalar     bool
	negative   bool
	saturating bool
}

// These are all six Go AVX512_4FMAPS/4VNNIW names. Their complete shared
// grammar is m128, a four-register range, optional K1-K7 and accumulator;
// only masked register zeroing is supported, not broadcast, ER or SAE.
var amd64FourSourceSpecs = map[Op]amd64FourSourceSpec{
	"V4FMADDPS":  {mode: amd64FourSourceFMA},
	"V4FMADDSS":  {mode: amd64FourSourceFMA, scalar: true},
	"V4FNMADDPS": {mode: amd64FourSourceFMA, negative: true},
	"V4FNMADDSS": {mode: amd64FourSourceFMA, scalar: true, negative: true},
	"VP4DPWSSD":  {mode: amd64FourSourceDotWords},
	"VP4DPWSSDS": {mode: amd64FourSourceDotWords, saturating: true},
}

type amd64FourSourceForm struct {
	spec        amd64FourSourceSpec
	memory      Operand
	sourceBase  int
	destination Operand
	maskIndex   int
	zeroing     bool
}

func (form amd64FourSourceForm) byteWidth() int {
	if form.spec.scalar {
		return 16
	}
	return 64
}

func (form amd64FourSourceForm) inputBytes() int64 {
	if form.spec.scalar {
		return 4
	}
	return 64
}

func (form amd64FourSourceForm) source(index int) Operand {
	bank := "Z"
	if form.spec.scalar {
		bank = "X"
	}
	return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", bank, form.sourceBase+index))}
}

func x86FourSourceProperties(op Op, ins Instr, arch string) (amd64FourSourceForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64FourSourceSpecs[Op(base)]
	form := amd64FourSourceForm{spec: spec, maskIndex: -1, zeroing: suffix == "Z"}
	if !known {
		return form, false, nil
	}
	fail := func() (amd64FourSourceForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go four-source grammar: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		dotted && suffix == "" || suffix != "" && suffix != "Z" || len(ins.Args) != 3 && len(ins.Args) != 4 ||
		arch == "386" && len(ins.Args) == 4 || suffix == "Z" && len(ins.Args) != 4 {
		return fail()
	}
	form.memory, form.destination = ins.Args[0], ins.Args[len(ins.Args)-1]
	if !isAMD64MemoryOperand(form.memory) || !x86PackedShiftMemoryValid(form.memory, arch) ||
		x86NamedMultiplyMemoryError(form.memory, arch) != nil {
		return fail()
	}
	if form.memory.Kind == OpMem && form.memory.Mem.IndexExt != "" {
		return fail()
	}
	rangeOperand := ins.Args[1]
	if rangeOperand.Kind != OpRegList || !rangeOperand.RegListRange || len(rangeOperand.RegList) != 4 {
		return fail()
	}
	first := -1
	for position, register := range rangeOperand.RegList {
		index, valid := amd64VectorRegisterIndex(register, form.byteWidth())
		if !valid || arch == "386" && index >= 8 || position != 0 && index != first+position {
			return fail()
		}
		if position == 0 {
			first = index
		}
	}
	index, valid := amd64VectorRegisterIndex(form.destination.Reg, form.byteWidth())
	if form.destination.Kind != OpReg || !valid || arch == "386" && index >= 8 {
		return fail()
	}
	if len(ins.Args) == 4 {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return fail()
		}
		form.maskIndex = 2
	}
	// Hardware selects the aligned block containing the encoded first
	// register, not necessarily the literal spelling's four registers.
	form.sourceBase = first &^ 3
	return form, true, nil
}

func x86TypedFourSourceByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86FourSourceProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: form.memory, width: 16, read: true},
		{index: len(ins.Args) - 1, operand: form.destination, width: int64(form.byteWidth()), read: true, write: true},
	}}
	for position := 0; position < 4; position++ {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: 1, operand: form.source(position), width: form.inputBytes(), read: true,
		})
	}
	if form.maskIndex >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.maskIndex, operand: ins.Args[form.maskIndex], width: 8, read: true,
		})
	}
	return effect, true, nil
}
