package plan9asm

import (
	"fmt"
	"strings"
)

// Both members share Go's complete eighteen-row _yvpermilpd grammar. The
// immediate selects data bytes; variable control reads a separate vector.
var x86InLanePermuteBits = map[Op]int{"VPERMILPS": 32, "VPERMILPD": 64}

// Both permute families share their operand, mask and E4NF envelopes. Their
// selector topology and which variable operand is data remain distinct.
type x86ElementPermuteForm struct {
	bits, byteWidth, source, data, destination, mask, memory, memoryBytes int
	immediate, broadcast, zeroing, wholeVector                            bool
	selector                                                              uint8
}

func x86InLanePermuteProperties(op Op, ins Instr, arch string) (x86ElementPermuteForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86InLanePermuteBits[Op(base)]
	if !known {
		return x86ElementPermuteForm{}, false, nil
	}
	return x86ElementPermuteFormProperties(op, ins, arch, bits, false)
}

func x86ElementPermuteProperties(op Op, ins Instr, arch string) (x86ElementPermuteForm, bool, error) {
	if form, known, err := x86InLanePermuteProperties(op, ins, arch); known {
		return form, true, err
	}
	if form, known, err := x86QwordPermuteProperties(op, ins, arch); known {
		return form, true, err
	}
	return x86VariableDwordPermuteProperties(op, ins, arch)
}

func x86VariableDwordPermuteProperties(op Op, ins Instr, arch string) (x86ElementPermuteForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	switch base {
	case "VPERMD", "VPERMPS":
	default:
		return x86ElementPermuteForm{}, false, nil
	}
	form, known, err := x86ElementPermuteFormProperties(op, ins, arch, 32, true)
	if err == nil && form.immediate {
		err = fmt.Errorf("%s requires a vector index source, not an immediate", op)
	}
	return form, known, err
}

func x86ElementPermuteFormProperties(op Op, ins Instr, arch string, bits int, wholeVector bool) (x86ElementPermuteForm, bool, error) {
	_, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	f := x86ElementPermuteForm{bits: bits, wholeVector: wholeVector, source: 0, data: 1,
		destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86ElementPermuteForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go's complete element-permute grammar: %q", arch, op, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) != 3 && len(ins.Args) != 4 {
		return fail()
	}
	switch suffix {
	case "":
		if dotted {
			return fail()
		}
	case "Z":
		f.zeroing = true
	case "BCST":
		f.broadcast = true
	case "BCST.Z":
		f.broadcast, f.zeroing = true, true
	default:
		return fail()
	}
	if len(ins.Args) == 4 {
		if arch == "386" || !amd64NonzeroKOperand(ins.Args[2]) {
			return fail() // Named mode32's three-operand limit is not a physical EVEX restriction.
		}
		f.mask = 2
	} else if f.zeroing {
		return fail()
	}
	f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	register := func(operand Operand) bool {
		if !amd64EVEXVectorRegister(operand, f.byteWidth) {
			return false
		}
		index, _ := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
		return arch != "386" || f.byteWidth != 64 || index < 8
	}
	if f.byteWidth != 16 && f.byteWidth != 32 && f.byteWidth != 64 || wholeVector && f.byteWidth == 16 ||
		!register(ins.Args[f.destination]) {
		return fail()
	}
	f.immediate = ins.Args[0].Kind == OpImm
	if f.immediate {
		constant, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
		if !integer || constant.Imm < -128 || constant.Imm > 255 {
			return fail()
		}
		f.source, f.data, f.selector = 1, -1, uint8(constant.Imm)
		if constant.Imm < 0 && (f.broadcast || amd64PackedWordShuffleRequiresEVEX(
			ins.Args[f.source], ins.Args[f.destination], f.byteWidth, f.mask >= 0)) {
			return fail()
		}
	} else if !register(ins.Args[f.data]) {
		return fail()
	}
	source := ins.Args[f.source]
	if isAMD64MemoryOperand(source) && x86PackedShiftMemoryValid(source, arch) {
		f.memory, f.memoryBytes = f.source, f.byteWidth
		if f.broadcast {
			f.memoryBytes = bits / 8
		}
	} else if f.broadcast || !register(source) {
		return fail()
	}
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}

func (f x86ElementPermuteForm) sourceByte(output int) int {
	if f.broadcast {
		return output % (f.bits / 8)
	}
	bytes := f.bits / 8
	lane := output / bytes
	if f.wholeVector {
		return output/32*32 + int(f.selector>>uint(2*(lane%4))&3)*8 + output%8
	}
	control, mask := uint(lane), uint8(1)
	if f.bits == 32 {
		control, mask = uint(2*(lane%4)), 3
	}
	return output/16*16 + int(f.selector>>control&mask)*bytes + output%bytes
}

func x86TypedElementPermuteByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86ElementPermuteProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := f.byteWidth
	if f.memory >= 0 {
		width = f.memoryBytes
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: f.source, operand: ins.Args[f.source], width: int64(width), read: true},
		{index: f.destination, operand: ins.Args[f.destination], width: int64(f.byteWidth), write: true},
	}}
	if f.data >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: f.data, operand: ins.Args[f.data], width: int64(f.byteWidth), read: true})
	}
	if f.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: f.mask, operand: ins.Args[f.mask], width: 8, read: true})
		if !f.zeroing {
			effect.operands[1].read = true
		}
	}
	return effect, true, nil
}
