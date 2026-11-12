package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ExplicitMaskMoveSpec struct {
	laneBits int
}

// Go's complete _yvmaskmovpd table: X/Y load/store with vector sign-bit
// masks, not K writemasks. VMASKMOVPS/PD are W0, not WIG (W1 raises #UD).
var amd64ExplicitMaskMoveSpecs = map[Op]amd64ExplicitMaskMoveSpec{
	"VMASKMOVPS": {laneBits: 32},
	"VMASKMOVPD": {laneBits: 64},
	"VPMASKMOVD": {laneBits: 32},
	"VPMASKMOVQ": {laneBits: 64},
}

type x86ExplicitMaskMoveForm struct {
	spec      amd64ExplicitMaskMoveSpec
	byteWidth int
	memory    int
	load      bool
}

// Shape supplies no numerical mask bits, native address or frame backing.
func x86ExplicitMaskMoveProperties(op Op, ins Instr, arch string) (x86ExplicitMaskMoveForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64ExplicitMaskMoveSpecs[Op(name)]
	form := x86ExplicitMaskMoveForm{spec: spec}
	if !known {
		return form, false, nil
	}
	fail := func() (x86ExplicitMaskMoveForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go explicit vector-mask move grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 3 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	form.load = isAMD64MemoryOperand(ins.Args[0])
	if form.load == isAMD64MemoryOperand(ins.Args[2]) {
		return fail()
	}
	form.memory = 2
	data := ins.Args[0]
	if form.load {
		form.memory, data = 0, ins.Args[2]
	}
	form.byteWidth = amd64VectorByteWidth(ins.Args[1].Reg)
	if form.byteWidth != 16 && form.byteWidth != 32 ||
		!amd64VEXVectorRegister(ins.Args[1], form.byteWidth) || !amd64VEXVectorRegister(data, form.byteWidth) {
		return fail()
	}
	memory := ins.Args[form.memory]
	if memory.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(memory.Mem, arch); err != nil {
			return form, true, err
		}
		if memory.Mem.OffRaw != "" || memory.Mem.IndexExt != "" {
			return fail()
		}
		if arch == "386" && strings.HasSuffix(memory.Mem.Sym, "(SB)") {
			memory.Mem.Base = "" // Go ignores this annotation, not the index input.
		}
	}
	if !x86PackedShiftMemoryValid(memory, arch) {
		return fail()
	}
	return form, true, nil
}

// Only the byte containing each lane's most significant bit is an input.
func (f x86ExplicitMaskMoveForm) signByteInputs() uint64 {
	lane := f.spec.laneBits / 8
	var required uint64
	for offset := lane - 1; offset < f.byteWidth; offset += lane {
		required |= uint64(1) << uint(offset)
	}
	return required
}

func x86TypedExplicitMaskMoveByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86ExplicitMaskMoveProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return x86TypedByteEffect{}, true, err
	}
	width := int64(f.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: width, read: true},
		{index: 2, operand: ins.Args[2], width: width, write: true},
	}}, true, nil
}
