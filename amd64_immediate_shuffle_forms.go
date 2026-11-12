package plan9asm

import (
	"fmt"
	"strings"
)

type x86ImmediateShuffleSpec struct {
	laneBytes         int
	high, legacy, mmx bool
}

// Go's ymshuf/yxshuf and complete _yvpshufd rows share the four-element
// selector grammar. Only the dword EVEX spelling permits m32 broadcast.
var x86ImmediateShuffleSpecs = map[Op]x86ImmediateShuffleSpec{
	"PSHUFW":   {2, false, true, true},
	"PSHUFL":   {4, false, true, false},
	"PSHUFD":   {4, false, true, false},
	"PSHUFHW":  {2, true, true, false},
	"PSHUFLW":  {2, false, true, false},
	"VPSHUFD":  {4, false, false, false},
	"VPSHUFHW": {2, true, false, false},
	"VPSHUFLW": {2, false, false, false},
}

type x86ImmediateShuffleForm struct {
	spec                      x86ImmediateShuffleSpec
	source                    Operand
	destination, mask, memory int
	byteWidth, memoryBytes    int
	immediate                 uint8
	broadcast, zeroing        bool
}

// Immediate shuffles read one complete source, including the word half left
// in place. Unlike PSHUFB, the old destination is never an input unless it
// aliases that source. Memory extent/alignment remain separate obligations.
func x86TypedImmediateShuffleByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86ImmediateShuffleProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("immediate-shuffle dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	if !known || err != nil || !form.spec.legacy || form.spec.mmx {
		return x86TypedByteEffect{}, known && (err != nil || form.spec.legacy && !form.spec.mmx), err
	}
	return x86ImmediateShuffleDependencyEffect(ins, form), true, nil
}

// The admitted encoding chooses upper writes and memory alignment; both use
// one source-only dependency shape. This descriptor does not admit a form.
func x86ImmediateShuffleDependencyEffect(ins Instr, form x86ImmediateShuffleForm) x86TypedByteEffect {
	vector := x86TypedVectorEffect{x86TypedVectorUpperPreserve, 16}
	if !form.spec.legacy {
		vector = x86TypedVectorEffect{x86TypedVectorUpperZero, 1}
	}
	return x86TypedByteEffect{
		vector: vector,
		operands: []x86TypedByteOperand{
			{index: 1, operand: form.source, width: int64(form.byteWidth), read: true},
			{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true},
		},
	}
}

// This supplies encoding, native access extent and byte selectors, not source
// values, original pointer/alignment backing or permission to borrow an ABI.
func x86ImmediateShuffleProperties(ins Instr, arch string) (x86ImmediateShuffleForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86ImmediateShuffleSpecs[Op(base)]
	if !known {
		return x86ImmediateShuffleForm{}, false, nil
	}
	f := x86ImmediateShuffleForm{spec: spec, destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86ImmediateShuffleForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside Go immediate-shuffle grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || len(ins.Args) != 3 && len(ins.Args) != 4 {
		return fail()
	}
	immediate, integer := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !integer {
		return fail()
	}
	if spec.legacy {
		if dotted || len(ins.Args) != 3 || spec.mmx && !amd64SignedImmediate(immediate, 8) ||
			!spec.mmx && !amd64UnsignedImmediate(immediate, 8) {
			return fail()
		}
		f.byteWidth = 16
		if spec.mmx {
			f.byteWidth = 8
		}
	} else {
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
		if immediate.Imm < -128 || immediate.Imm > 255 || f.broadcast && spec.laneBytes != 4 {
			return fail()
		}
		if len(ins.Args) == 4 {
			if arch == "386" && !ins.x86Encoded || !amd64NonzeroKOperand(ins.Args[2]) {
				return fail()
			}
			f.mask = 2
		} else if f.zeroing {
			return fail()
		}
		f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	}
	register := func(operand Operand) bool {
		if operand.Kind != OpReg {
			return false
		}
		if spec.mmx {
			_, valid := amd64ParseMReg(operand.Reg)
			return valid
		}
		if spec.legacy {
			index, valid := amd64ParseXReg(operand.Reg)
			return valid && (arch == "amd64" && index < 16 || arch == "386" && index < 8)
		}
		return amd64GoPackedVectorMoveRegister(operand, f.byteWidth, arch)
	}
	if !register(ins.Args[f.destination]) {
		return fail()
	}
	local, err := x86LegacyMMXReadInstruction(ins, arch)
	if err != nil {
		return f, true, err
	}
	f.source = local.Args[1]
	if isAMD64MemoryOperand(f.source) && x86PackedShiftMemoryValid(f.source, arch) {
		f.memory, f.memoryBytes = 1, f.byteWidth
		if f.broadcast {
			f.memoryBytes = 4
		}
	} else if f.broadcast || !register(f.source) {
		return fail()
	}
	if !spec.legacy && immediate.Imm < 0 &&
		(f.broadcast || amd64PackedWordShuffleRequiresEVEX(f.source, ins.Args[f.destination], f.byteWidth, f.mask >= 0)) {
		return fail()
	}
	f.immediate = uint8(immediate.Imm)
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}

func x86ImmediateShuffleConstant(operand Operand, arch string, encoded bool) (Operand, bool) {
	if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" {
		return operand, false
	}
	// Go's I386 oclass classifies TYPE_CONST after signed int32 truncation;
	// retain the original operand, but use its classified value for every row.
	if arch == "386" && !encoded {
		operand.Imm = int64(int32(operand.Imm))
	}
	return operand, true
}

// Every output byte depends on exactly one source byte; the word half not
// shuffled still comes from the source, never the old destination.
func (f x86ImmediateShuffleForm) sourceByte(destination int) int {
	if f.broadcast {
		return destination % 4
	}
	groupBytes := 16
	if f.spec.mmx {
		groupBytes = 8
	}
	lane := destination % groupBytes / f.spec.laneBytes
	if f.spec.laneBytes == 2 && !f.spec.mmx && (lane < 4) == f.spec.high {
		return destination
	}
	half := 0
	if f.spec.high {
		half = 8
	}
	return destination/groupBytes*groupBytes + half +
		int(f.immediate>>(2*(lane%4))&3)*f.spec.laneBytes + destination%f.spec.laneBytes
}
