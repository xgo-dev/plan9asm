package plan9asm

import (
	"fmt"
	"strings"
)

var amd64Shuffle128BitBlockLaneBits = map[string]int{
	"VSHUFF32X4": 32,
	"VSHUFI32X4": 32,
	"VSHUFF64X2": 64,
	"VSHUFI64X2": 64,
}

type x86Shuffle128BitBlocksForm struct {
	x86PackedBinaryForm
	laneBits  int
	immediate uint8
}

func x86Shuffle128BitBlocksProperties(op Op, ins Instr, arch string) (x86Shuffle128BitBlocksForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := amd64Shuffle128BitBlockLaneBits[base]
	f := x86Shuffle128BitBlocksForm{laneBits: bits}
	if !known {
		return f, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) != 4 && len(ins.Args) != 5 || arch == "386" && (!ins.x86Encoded || len(ins.Args) == 5) {
		return f, true, fmt.Errorf("%s %s has an unbound dispatch or operand count", arch, op)
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer || !amd64UnsignedImmediate(immediate, 8) {
		return f, true, fmt.Errorf("%s requires its unsigned-byte selector", op)
	}
	local := ins
	local.Op, local.Args = op, ins.Args[1:]
	form, err := x86ConflictFunnelOperandGrammar(local, arch,
		x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: bits / 8, zeroing: true}, false)
	form.first++
	form.second++
	form.destination++
	if form.mask >= 0 {
		form.mask++
	}
	if form.memory >= 0 {
		form.memory++
	}
	f.x86PackedBinaryForm, f.immediate = form, uint8(immediate.Imm)
	if err == nil && form.byteWidth != 32 && form.byteWidth != 64 {
		err = fmt.Errorf("%s requires a Y or Z carrier", op)
	}
	return f, true, err
}

func x86TypedShuffle128BitBlocksByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86Shuffle128BitBlocksProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedFixedVectorInputs(ins, form.x86PackedBinaryForm, false), true, nil
}
