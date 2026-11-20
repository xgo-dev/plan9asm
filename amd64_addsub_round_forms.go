package plan9asm

import (
	"fmt"
	"strings"
)

// Alternating add/sub uses the existing floating dependency record, with
// its own complete legacy/VEX grammar and no EVEX mask or rounding forms.
func x86AlternatingFloatProperties(ins Instr, arch string) (x86FloatBinaryForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	f := x86FloatBinaryForm{first: 0, second: 1, destination: len(ins.Args) - 1, mask: -1, memory: -1, byteWidth: 16}
	switch name {
	case "ADDSUBPS":
		f.bits, f.legacy = 32, true
	case "ADDSUBPD":
		f.bits, f.legacy = 64, true
	case "VADDSUBPS":
		f.bits = 32
	case "VADDSUBPD":
		f.bits = 64
	default:
		return f, false, nil
	}
	if dotted {
		return f, true, fmt.Errorf("%s %s has no suffixed forms in Go 1.27: %q", arch, name, ins.Raw)
	}
	legacyRegister := func(operand Operand) bool {
		index, valid := amd64ParseXReg(operand.Reg)
		return operand.Kind == OpReg && valid && index < 16 && (arch != "386" || index < 8)
	}
	if f.legacy {
		if len(ins.Args) != 2 || !legacyRegister(ins.Args[1]) {
			return f, true, fmt.Errorf("%s %s expects X/m128, X using Go 1.27's yxm table: %q", arch, name, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if !legacyRegister(ins.Args[0]) {
				return f, true, fmt.Errorf("%s %s source is outside the legacy X class: %q", arch, name, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return f, true, fmt.Errorf("%s %s source must be X or memory: %q", arch, name, ins.Raw)
		}
	} else {
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpReg {
			return f, true, fmt.Errorf("%s %s expects src1, src2, destination: %q", arch, name, ins.Raw)
		}
		f.byteWidth = amd64VectorByteWidth(ins.Args[2].Reg)
		if f.byteWidth != 16 && f.byteWidth != 32 || !amd64VEXVectorRegister(ins.Args[1], f.byteWidth) || !amd64VEXVectorRegister(ins.Args[2], f.byteWidth) {
			return f, true, fmt.Errorf("%s %s second source and destination must be same-width VEX X/Y registers: %q", arch, name, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if !amd64VEXVectorRegister(ins.Args[0], f.byteWidth) {
				return f, true, fmt.Errorf("%s %s first source must match the destination width: %q", arch, name, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return f, true, fmt.Errorf("%s %s first source must be a vector register or memory: %q", arch, name, ins.Raw)
		}
	}
	if isAMD64MemoryOperand(ins.Args[0]) {
		f.memory, f.memoryBytes = 0, f.byteWidth
	}
	return f, true, nil
}

type x86RoundForm struct {
	spec                       amd64RoundSpec
	source, upper, destination Operand
	byteWidth, memoryBytes     int
	immediate                  uint8
	memory                     bool
}

// The original single round spec remains the only operation selector. Scalar
// source bytes and upper-copy bytes stay separate from the X/Y carrier.
func x86RoundProperties(ins Instr, arch string) (x86RoundForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64RoundSpecs[Op(name)]
	f := x86RoundForm{spec: spec}
	if !known {
		return f, false, nil
	}
	if dotted {
		return f, true, fmt.Errorf("%s %s does not accept instruction suffixes: %q", arch, name, ins.Raw)
	}
	want := 3
	if spec.vector && spec.scalar {
		want = 4
	}
	if len(ins.Args) != want {
		return f, true, fmt.Errorf("%s %s expects immediate, source, %sdestination: %q", arch, name, map[bool]string{true: "upper-lane source, "}[spec.vector && spec.scalar], ins.Raw)
	}
	// I386's ordinary Go frontend does not accept this four-operand form.
	// A normalized encoded instruction retains its separate physical grammar.
	if arch == "386" && spec.vector && spec.scalar && !ins.x86Encoded && ins.x86SourceRaw == nil {
		return f, true, fmt.Errorf("%s %s four-operand form is not accepted by Go's frontend: %q", arch, name, ins.Raw)
	}
	immediate := ins.Args[0]
	if !amd64UnsignedImmediate(immediate, 8) &&
		!(spec.vector && !spec.scalar && amd64VectorByteShiftImmediate(immediate)) {
		return f, true, fmt.Errorf("%s %s expects an integer immediate within Go's 8-bit table: %q", arch, name, ins.Raw)
	}
	imm := immediate.Imm
	f.immediate, f.source, f.destination = uint8(imm), ins.Args[1], ins.Args[len(ins.Args)-1]
	if f.destination.Kind != OpReg {
		return f, true, fmt.Errorf("%s %s destination must be a vector register: %q", arch, name, ins.Raw)
	}
	f.byteWidth = amd64VectorByteWidth(f.destination.Reg)
	register := func(operand Operand, width int, memory bool) bool {
		if memory && isAMD64MemoryOperand(operand) {
			return true
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, width)
		return amd64VEXVectorRegister(operand, width) && valid && (arch != "386" || index < 8)
	}
	if spec.scalar {
		if f.byteWidth != 16 || !register(f.destination, 16, false) {
			return f, true, fmt.Errorf("%s %s destination must be an X register in the Go VEX class: %q", arch, name, ins.Raw)
		}
	} else if !spec.vector && f.byteWidth != 16 || spec.vector && f.byteWidth != 16 && f.byteWidth != 32 || !register(f.destination, f.byteWidth, false) {
		return f, true, fmt.Errorf("%s %s destination has a width outside Go 1.27's table: %q", arch, name, ins.Raw)
	}
	if !register(f.source, f.byteWidth, true) {
		return f, true, fmt.Errorf("%s %s source must be same-width X/Y or memory: %q", arch, name, ins.Raw)
	}
	f.upper = f.destination
	if spec.vector && spec.scalar {
		f.upper = ins.Args[2]
		if !register(f.upper, 16, false) {
			return f, true, fmt.Errorf("%s %s upper-lane source must be an X register: %q", arch, name, ins.Raw)
		}
	}
	f.memory, f.memoryBytes = isAMD64MemoryOperand(f.source), f.byteWidth
	if spec.scalar {
		f.memoryBytes = spec.laneBits / 8
	}
	return f, true, nil
}

func x86TypedAlternatingFloatByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	f, known, err := x86AlternatingFloatProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		err = fmt.Errorf("alternating floating dispatch/source opcode mismatch")
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: f.first, operand: ins.Args[f.first], width: int64(f.byteWidth), read: true},
		{index: f.second, operand: ins.Args[f.second], width: int64(f.byteWidth), read: true},
		{index: f.destination, operand: ins.Args[f.destination], width: int64(f.byteWidth), write: true},
	}}
	effect.vector.upperWrite = x86TypedVectorUpperZero
	if f.legacy {
		effect.vector.upperWrite = x86TypedVectorUpperPreserve
	}
	return effect, true, nil
}

func x86TypedRoundByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	f, known, err := x86RoundProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		err = fmt.Errorf("round dispatch/source opcode mismatch")
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: 1, read: true},
		{index: 1, operand: f.source, width: int64(f.memoryBytes), read: true},
	}}
	if f.spec.scalar {
		upper := len(ins.Args) - 1
		if f.spec.vector {
			upper = 2
		}
		effect.operands = append(effect.operands, x86TypedByteOperand{index: upper, operand: f.upper, width: 16, read: true, requiredBytes: 0xffff &^ x86CallerVectorByteMask(int64(f.memoryBytes))})
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{index: len(ins.Args) - 1, operand: f.destination, width: int64(f.byteWidth), write: true})
	effect.vector.upperWrite = x86TypedVectorUpperZero
	if !f.spec.vector {
		effect.vector.upperWrite = x86TypedVectorUpperPreserve
	}
	return effect, true, nil
}
