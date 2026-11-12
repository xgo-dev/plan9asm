package plan9asm

import (
	"fmt"
	"strings"
)

type x86DuplicateMoveSpec struct {
	laneBytes int
	odd       bool
	vector    bool
}

// All three legacy yxm and all three shared _yvmovddup rows. The selector
// describes numerical bytes; it never reduces the native memory access tuple.
var x86DuplicateMoveSpecs = map[Op]x86DuplicateMoveSpec{
	"MOVDDUP": {8, false, false}, "MOVSHDUP": {4, true, false}, "MOVSLDUP": {4, false, false},
	"VMOVDDUP": {8, false, true}, "VMOVSHDUP": {4, true, true}, "VMOVSLDUP": {4, false, true},
}

type x86DuplicateMoveForm struct {
	x86PackedBinaryForm
	spec   x86DuplicateMoveSpec
	source Operand
}

func x86DuplicateMoveProperties(op Op, ins Instr, arch string) (x86DuplicateMoveForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86DuplicateMoveSpecs[Op(base)]
	form := x86DuplicateMoveForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return form, true, fmt.Errorf("%s %s has an unbound dispatch or unary operand count", arch, op)
	}
	local, grammar := ins, x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}
	local.Op = op
	if spec.vector {
		grammar.encoding, grammar.zeroing = x86PackedLogicalVEXOrEVEX, true
		destination := ins.Args[len(ins.Args)-1]
		local.Args = []Operand{ins.Args[0], destination, destination}
		if len(ins.Args) == 3 {
			local.Args = []Operand{ins.Args[0], destination, ins.Args[1], destination}
		}
	}
	var err error
	form.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, grammar, spec.vector)
	form.second, form.destination = -1, len(ins.Args)-1
	if form.mask >= 0 {
		form.mask = 1
	}
	if form.memory >= 0 && spec.laneBytes == 8 && form.byteWidth == 16 {
		form.memoryBytes = 8 // Only X-width DDUP reads one scalar qword.
	}
	form.source = ins.Args[0]
	return form, true, err
}

func (form x86DuplicateMoveForm) sourceByte(output int) int {
	lane := output / form.spec.laneBytes
	if form.spec.odd {
		lane |= 1
	} else {
		lane &^= 1
	}
	return lane*form.spec.laneBytes + output%form.spec.laneBytes
}

func (form x86DuplicateMoveForm) sourceMask() uint64 {
	var mask uint64
	for output := 0; output < form.byteWidth; output++ {
		mask |= uint64(1) << uint(form.sourceByte(output))
	}
	return mask
}

func x86ResultDuplicateMoveStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	widthMask := x86CallerVectorByteMask(int64(form.byteWidth))
	if form.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[form.mask].Reg)
		if !state.masks[mask] || !form.zeroing && state.vectorBytes(destination)&widthMask != widthMask {
			return false, true
		}
	}
	if form.memory >= 0 {
		if form.legacy && form.spec.laneBytes == 4 {
			// Virtual FP/AUTO bytes are not the original aligned m128.
			if _, static := x86StaticSBReadAddress(form.source, arch); !static &&
				(!nativeRead || !x86OrdinaryNativeMemoryOperand(form.source, arch)) {
				return false, true
			}
		}
		if !x86ResultReadWithNativeContinuation(ins, form.source, int64(form.memoryBytes), state, owned, arch, nativeRead) {
			return false, true
		}
	} else {
		source, _ := amd64VectorRegisterIndex(form.source.Reg, form.byteWidth)
		required := form.sourceMask()
		if state.vectorBytes(source)&required != required {
			return false, true
		}
	}
	// Every potentially selected numerical byte is now known. All reads,
	// including an aliased source and masked merge, precede any output write.
	state.writeVector(destination, form.byteWidth, widthMask, form.legacy)
	return true, true
}
