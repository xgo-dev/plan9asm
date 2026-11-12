package plan9asm

import (
	"fmt"
	"strings"
)

type amd64HorizontalIntegerSpec struct {
	laneBits int
	subtract bool
	saturate bool
	vector   bool
	allowMMX bool
	// VEX.66.0F38 opcode, shared by raw decoding and typed lowering.
	opcode byte
}

// The complete PHADD/PHSUB family has one exceptional legacy MMX row:
// PHADDD's ymmxmm0f38. Its siblings use yxm_q4; VEX uses X/Y only.
var amd64HorizontalIntegerSpecs = map[Op]amd64HorizontalIntegerSpec{
	"PHADDD":   {laneBits: 32, allowMMX: true},
	"PHADDSW":  {laneBits: 16, saturate: true},
	"PHADDW":   {laneBits: 16},
	"PHSUBD":   {laneBits: 32, subtract: true},
	"PHSUBSW":  {laneBits: 16, subtract: true, saturate: true},
	"PHSUBW":   {laneBits: 16, subtract: true},
	"VPHADDD":  {laneBits: 32, vector: true, opcode: 0x02},
	"VPHADDSW": {laneBits: 16, saturate: true, vector: true, opcode: 0x03},
	"VPHADDW":  {laneBits: 16, vector: true, opcode: 0x01},
	"VPHSUBD":  {laneBits: 32, subtract: true, vector: true, opcode: 0x06},
	"VPHSUBSW": {laneBits: 16, subtract: true, saturate: true, vector: true, opcode: 0x07},
	"VPHSUBW":  {laneBits: 16, subtract: true, vector: true, opcode: 0x05},
}

type x86HorizontalIntegerForm struct {
	spec                               amd64HorizontalIntegerSpec
	first, second, destination, memory int
	byteWidth                          int
	mmx                                bool
}

// Forms describe ordered bytes and encoding only; they confer no caller,
// stack, alignment, MMX state or address permission.
func x86HorizontalIntegerProperties(ins Instr, arch string) (x86HorizontalIntegerForm, bool, error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64HorizontalIntegerSpecs[Op(base)]
	if !known {
		return x86HorizontalIntegerForm{}, false, nil
	}
	form := x86HorizontalIntegerForm{spec: spec, first: 0, second: 1, destination: len(ins.Args) - 1, memory: -1, byteWidth: 16}
	fail := func() (x86HorizontalIntegerForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go horizontal integer grammar: %q", arch, ins.Op, ins.Raw)
	}
	if dotted || arch != "amd64" && arch != "386" || !spec.vector && len(ins.Args) != 2 || spec.vector && len(ins.Args) != 3 {
		return fail()
	}
	if spec.allowMMX {
		legacy, _, err := x86LegacyMMXReadProperties(ins, arch)
		if err != nil {
			return form, true, err
		}
		if err := x86LegacyMMXReadEmitterContext(ins, arch); err != nil {
			return form, true, err
		}
		form.mmx, form.byteWidth = legacy.mmx, legacy.byteWidth
		if legacy.memoryBytes != 0 {
			form.memory = 0
		}
		return form, true, nil
	}
	if spec.vector {
		form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
		if form.byteWidth != 16 && form.byteWidth != 32 {
			return fail()
		}
	}
	register := func(operand Operand) bool {
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		return operand.Kind == OpReg && valid && index < 16 && (spec.vector || arch == "amd64" || index < 8)
	}
	if !register(ins.Args[form.second]) || !register(ins.Args[form.destination]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) && x86PackedShiftMemoryValid(first, arch) {
		form.memory = form.first
	} else if !register(first) {
		return fail()
	}
	if spec.vector {
		if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
			return form, true, err
		}
	}
	return form, true, nil
}

func x86CallerHorizontalIntegerStep(ins *Instr, form x86HorizontalIntegerForm, state *x86SourceStackState, proof *x86GoCallerRegionProof) bool {
	if form.mmx {
		return false
	}
	required := x86CallerVectorByteMask(int64(form.byteWidth))
	// Require all potential input bytes before certifying memory or writing
	// aliases. Horizontal subtract with equal operands is not a zero idiom.
	for _, index := range []int{form.first, form.second} {
		if index != form.memory && state.vectors[x86CallerVectorRoot(ins.Args[index].Reg)]&required != required {
			return false
		}
	}
	if form.memory >= 0 {
		// No current caller producer supplies the actual legacy m128 alignment.
		if !form.spec.vector || !x86CallerOrdinaryMemoryStep(ins, form.memory, state, proof, int64(form.byteWidth), false) {
			return false
		}
	}
	destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
	known := ^uint64(0)
	if !form.spec.vector {
		known = state.vectors[destination] | required
	}
	state.vectors[destination] = known
	return true
}
