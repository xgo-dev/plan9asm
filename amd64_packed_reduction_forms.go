package plan9asm

import (
	"fmt"
	"strings"
)

// These two arithmetic families share a two-source native reduction envelope,
// not an arithmetic formula. Horizontal pairs consume every input byte; dot
// products consume only imm-selected lanes while still reading the full native
// memory tuple and retaining the opcode's complete exception/MXCSR effects.
type x86PackedReductionForm struct {
	first, second, destination, memory int
	byteWidth, laneBits                int
	dot, legacy                        bool
	immediate                          uint8
}

func x86PackedReductionProperties(ins Instr, arch string) (x86PackedReductionForm, bool, error) {
	if horizontal, known, err := x86HorizontalFloatProperties(ins, arch); known {
		return x86PackedReductionForm{
			first: horizontal.first, second: horizontal.second, destination: horizontal.destination,
			memory: horizontal.memory, byteWidth: horizontal.byteWidth, laneBits: horizontal.spec.laneBits,
			legacy: !horizontal.spec.vector,
		}, true, err
	}
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64PackedFloatingDotSpecs[Op(base)]
	form := x86PackedReductionForm{
		first: 1, second: 2, destination: 2, memory: -1,
		byteWidth: 16, laneBits: spec.laneBits, dot: true, legacy: spec.form == amd64PackedFloatingDotLegacy,
	}
	if !known {
		return form, false, nil
	}
	fail := func() (x86PackedReductionForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go dot-product grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted {
		return fail()
	}
	count := 3
	if !form.legacy {
		count, form.destination = 4, 3
	}
	if len(ins.Args) != count || arch == "386" && !form.legacy && !ins.x86Encoded && ins.x86SourceRaw == nil {
		return fail()
	}
	immediate, valid := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !valid || !amd64UnsignedImmediate(immediate, 8) {
		return fail()
	}
	form.immediate = uint8(immediate.Imm)
	if !form.legacy {
		form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
	}
	if form.byteWidth != 16 && (spec.form != amd64PackedFloatingDotVEX128Or256 || form.byteWidth != 32) {
		return fail()
	}
	register := func(operand Operand) bool {
		index, ok := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		return operand.Kind == OpReg && ok && index < 16 && (arch != "386" || index < 8)
	}
	if !register(ins.Args[form.second]) || !register(ins.Args[form.destination]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) {
		if !x86PackedShiftMemoryValid(first, arch) {
			return fail()
		}
		if first.Kind == OpMem && (x86SymbolIndexedMemoryError(first.Mem, arch) != nil || first.Mem.OffRaw != "" || first.Mem.IndexExt != "") {
			return fail()
		}
		form.memory = form.first
	} else if !register(first) {
		return fail()
	}
	return form, true, nil
}

func (form x86PackedReductionForm) inputBytes() uint64 {
	if !form.dot {
		return x86CallerVectorByteMask(int64(form.byteWidth))
	}
	var result uint64
	bytes := form.laneBits / 8
	for block := 0; block < form.byteWidth; block += 16 {
		for lane := 0; lane < 16/bytes; lane++ {
			if form.immediate&(1<<uint(lane+4)) != 0 {
				result |= x86CallerVectorByteMask(int64(bytes)) << uint(block+lane*bytes)
			}
		}
	}
	return result
}

func x86TypedPackedReductionByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86PackedReductionProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		err = fmt.Errorf("reduction dispatch/source opcode mismatch")
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: width, read: true},
		{index: form.second, operand: ins.Args[form.second], width: width, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: width, write: true},
	}}, true, nil
}
