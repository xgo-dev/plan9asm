package plan9asm

import (
	"fmt"
	"strings"
)

type x86ImmediateBlendForm struct {
	source, base, destination int
	byteWidth, laneBytes      int
	selector                  uint8
	legacy, memory            bool
}

// Go's yxshuf and _yvblendpd supply eleven rows, not an EVEX family.
// Physical mode32 VEX has its own decoder role; its four operands do not
// become legal genuine named Go386 syntax.
func x86ImmediateBlendProperties(op Op, ins Instr, arch string) (x86ImmediateBlendForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, vector, known := amd64ImmediatePackedBlendProperties(name)
	f := x86ImmediateBlendForm{source: 1, base: 2, destination: 2, laneBytes: bits / 8, legacy: !vector}
	if !known {
		return f, false, nil
	}
	fail := func() (x86ImmediateBlendForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go immediate-blend grammar: %q", arch, op, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	if vector {
		f.destination = 3
	}
	if len(ins.Args) != f.destination+1 || arch == "386" && vector && !ins.x86Encoded {
		return fail()
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || immediate.Imm < 0 || immediate.Imm > 255 {
		return fail()
	}
	f.selector = uint8(immediate.Imm)
	f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	if f.byteWidth != 16 && (f.legacy || f.byteWidth != 32) {
		return fail()
	}
	register := func(operand Operand) bool {
		if !amd64VEXVectorRegister(operand, f.byteWidth) {
			return false
		}
		index, _ := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
		return arch != "386" || index < 8
	}
	if !register(ins.Args[f.destination]) || !register(ins.Args[f.base]) {
		return fail()
	}
	source := ins.Args[f.source]
	f.memory = isAMD64MemoryOperand(source)
	if !register(source) && (!f.memory || !x86PackedShiftMemoryValid(source, arch)) {
		return fail()
	}
	return f, true, nil
}

func (f x86ImmediateBlendForm) selectsFirst(output int) bool {
	return f.selector>>uint(output/f.laneBytes%8)&1 != 0
}

func x86TypedImmediateBlendByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86ImmediateBlendProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: f.source, operand: ins.Args[f.source], width: int64(f.byteWidth), read: true},
		{index: f.base, operand: ins.Args[f.base], width: int64(f.byteWidth), read: true},
		{index: f.destination, operand: ins.Args[f.destination], width: int64(f.byteWidth), write: true},
	}}, true, nil
}
