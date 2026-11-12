package plan9asm

import (
	"fmt"
	"strings"
)

type x86UnalignedLoadForm struct {
	byteWidth int
	spec      amd64UnalignedLoadSpec
}

func x86UnalignedLoadProperties(op Op, ins Instr, arch string) (x86UnalignedLoadForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64UnalignedLoadSpecs[Op(name)]
	form := x86UnalignedLoadForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86UnalignedLoadForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go unaligned-load grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		!isAMD64MemoryOperand(ins.Args[0]) || ins.Args[1].Kind != OpReg {
		return fail()
	}
	form.byteWidth = amd64VectorByteWidth(ins.Args[1].Reg)
	index, vector := amd64VectorRegisterIndex(ins.Args[1].Reg, form.byteWidth)
	if !vector || form.byteWidth != 16 && form.byteWidth != 32 || form.byteWidth > spec.maxBytes ||
		index >= 16 || !spec.vector && arch == "386" && index >= 8 {
		return fail()
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, true, err
	}
	local, contextual := ins, false
	if spec.vector {
		local, contextual = x86VectorValueMemoryInput(ins, arch)
	}
	if !x86PackedShiftMemoryValid(local.Args[0], arch) {
		return fail()
	}
	if err := x86NamedMultiplyMemoryError(ins.Args[0], arch); err != nil {
		return form, true, err
	}
	if contextual {
		return form, true, x86VectorValueMemoryContext(ins)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return form, true, fmt.Errorf("%w: LDDQU needs its original native address mode", ErrProbeNeedsContext)
	}
	return form, true, nil
}

func x86TypedUnalignedLoadByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86UnalignedLoadProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: width, write: true},
	}}, true, nil
}

func x86RawUnalignedLoadSource(ins Instr, arch string) bool {
	_, known, err := x86UnalignedLoadProperties(ins.Op, ins, arch)
	return known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

// The original opcode can perform implementation-dependent wider/repeated
// native reads and optional #AC. Logical FP bytes are not that backing.
func x86ResultUnalignedLoadStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86UnalignedLoadProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !native || !x86ResultNamedPredicateInstruction(ins) && !x86RawUnalignedLoadSource(ins, arch) || ins.Args[0].Kind == OpFP {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	if !x86ResultReadWithNativeContinuation(local, ins.Args[0], int64(form.byteWidth), state, owned, arch, true) {
		return false, true
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[1].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, x86CallerVectorByteMask(int64(form.byteWidth)), !form.spec.vector)
	return true, true
}
