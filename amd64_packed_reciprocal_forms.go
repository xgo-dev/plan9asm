package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedReciprocalForm struct {
	op        Op
	byteWidth int
	legacy    bool
}

// Go's yxm and _yvptest tables have only X/m128 and VEX X/Y packed
// estimates. Scalar estimates, EVEX, masks and suffixes are separate grammars.
func x86PackedReciprocalProperties(op Op, ins Instr, arch string) (x86PackedReciprocalForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	form := x86PackedReciprocalForm{op: Op(name)}
	switch name {
	case "RCPPS", "RSQRTPS":
		form.legacy = true
	case "VRCPPS", "VRSQRTPS":
	default:
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86PackedReciprocalForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go packed reciprocal grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	form.byteWidth = amd64VectorByteWidth(ins.Args[1].Reg)
	vector := func(operand Operand) bool {
		if !form.legacy {
			return amd64VEXVectorRegister(operand, form.byteWidth)
		}
		index, valid := amd64ParseXReg(operand.Reg)
		limit := 16
		if arch == "386" {
			limit = 8
		}
		return operand.Kind == OpReg && valid && index < limit
	}
	if form.byteWidth != 16 && (form.legacy || form.byteWidth != 32) || !vector(ins.Args[1]) {
		return fail()
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !vector(source) {
			return fail()
		}
	} else if !form.legacy && x86Mode32UnboundVEXMemorySource(source, arch) {
		return form, true, fmt.Errorf("%w: 386 %s extended source base has no physical address binding", ErrProbeNeedsContext, op)
	} else if !isAMD64MemoryOperand(source) || !x86PackedShiftMemoryValid(source, arch) {
		return fail()
	} else if err := x86NamedMultiplyMemoryError(source, arch); err != nil {
		return form, true, err
	}
	return form, true, x86Mode32VectorRegisterContext(ins, arch)
}

func x86TypedPackedReciprocalByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedReciprocalProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	vector := x86TypedVectorEffect{upperWrite: x86TypedVectorUpperZero, memoryAlignment: 1}
	if form.legacy {
		vector.upperWrite, vector.memoryAlignment = x86TypedVectorUpperPreserve, 16
	}
	width := int64(form.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, vector: vector, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: width, write: true},
	}}, true, nil
}

func x86ResultPackedReciprocalStep(ins Instr, state *x86ResultState, owned []bool, arch string, native bool) (bool, bool) {
	form, known, err := x86PackedReciprocalProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	source, mask := ins.Args[0], x86CallerVectorByteMask(int64(form.byteWidth))
	defined := mask
	if source.Kind == OpReg {
		index, _ := amd64VectorRegisterIndex(source.Reg, form.byteWidth)
		if state.vectorBytes(index)&mask != mask {
			defined = 0 // Pure dead estimates may retain an unknown numerical value.
		}
	} else {
		// Virtual FP bytes are not an aligned native m128 operand. The
		// paired original opcode, rather than storage permission, owns #GP.
		if form.legacy {
			if _, static := x86StaticSBReadAddress(source, arch); !static &&
				(!native || !x86OrdinaryNativeMemoryOperand(source, arch)) {
				return false, true
			}
		}
		if !x86ResultReadWithNativeContinuation(ins, source, int64(form.byteWidth), state, owned, arch, native) {
			return false, true
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[1].Reg, form.byteWidth)
	state.writeVector(destination, form.byteWidth, defined, form.legacy)
	return true, true // No FLAGS, DF, MXCSR or storage facts change.
}
