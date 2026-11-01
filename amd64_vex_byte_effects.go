package plan9asm

import "strings"

// This is a typed dependency adapter, not a source/storage authority or an
// opcode whitelist. Each family retains its complete existing operand parser.
// The current consumer explicitly closes only non-masked VEX; EVEX storage,
// writemasks and EVEX broadcasts remain with their separately validated owners.
func x86UnmaskedVEXByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !strings.HasPrefix(strings.ToUpper(string(op)), "V") {
		return x86TypedByteEffect{}, false, nil
	}
	if form, known, err := x86PackedIntegerAddProperties(ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm, true, err)
	}
	if form, known, err := x86PackedSubtractProperties(ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm, true, err)
	}
	if form, known, err := x86PackedBinaryEffectProperties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm, form.vex, err)
	}
	if form, known, err := x86IntegerMinMaxProperties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm, form.spec.laneBits <= 32, err)
	}
	if form, known, err := x86PackedLogicalProperties(ins, arch); known {
		effect, known, err := x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm,
			form.spec.encoding != x86PackedLogicalEVEX, err)
		if err == nil {
			effect = x86PackedLogicalZeroDependencies(ins, form, effect)
		}
		return effect, known, err
	}
	if form, known, err := x86ByteShuffleProperties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form, true, err)
	}
	if form, known, err := x86CLMULProperties(op, ins, arch); known {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if form.legacy || !x86LowVEXVectorOperands(ins) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("carryless-multiply effect requires its separate non-VEX consumer: %s", ins.Op)
		}
		return x86CLMULDependencyEffect(ins, form), true, nil
	}
	local := ins
	local.Op = op
	if form, known, err := x86InsertExtractProperties(local, arch); known && !form.spec.scalar {
		if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("block-transfer dispatch/source mismatch: %s/%s", op, ins.Op)
		}
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if !form.spec.vex || !x86LowVEXVectorOperands(ins) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("block-transfer effect requires its separate non-VEX consumer: %s", ins.Op)
		}
		return x86BlockTransferDependencyEffect(ins, form), true, nil
	}
	if form, known, err := x86ImmediateShuffleProperties(local, arch); known {
		if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("immediate-shuffle dispatch/source mismatch: %s/%s", op, ins.Op)
		}
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if form.spec.legacy || form.spec.mmx || form.mask >= 0 || form.broadcast || form.zeroing || !x86LowVEXVectorOperands(ins) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("shuffle effect requires its separate non-VEX consumer: %s", ins.Op)
		}
		return x86ImmediateShuffleDependencyEffect(ins, form), true, nil
	}
	if form, known, err := x86PackedAlignProperties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm,
			form.spec.encoding != x86PackedLogicalEVEX, err)
	}
	if form, known, err := x86ImmediateBlendProperties(op, ins, arch); known {
		binary := x86PackedBinaryForm{
			byteWidth: form.byteWidth, first: form.source, second: form.base, destination: form.destination,
			legacy: form.legacy, mask: -1, memory: -1,
		}
		if form.memory {
			binary.memory, binary.memoryBytes = form.source, form.byteWidth
		}
		return x86UnmaskedVEXBinaryEffect(ins, binary, true, err)
	}
	if form, known, err := x86Permute128Properties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form.x86PackedBinaryForm, true, err)
	}
	if form, known, err := x86PackedShiftProperties(op, ins, arch); known {
		return x86UnmaskedVEXShiftEffect(ins, form, err)
	}
	if form, known, err := x86BroadcastProperties(op, ins, arch); known {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if !form.vex || form.mask >= 0 || form.zeroing || !x86LowVEXVectorOperands(ins) || ins.Args[0].Kind == OpImm {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("broadcast effect requires its separate non-VEX consumer: %s", ins.Op)
		}
		source := x86TypedByteOperand{index: 0, operand: ins.Args[0], width: int64(form.sourceBytes), read: true}
		if source.operand.Kind == OpReg {
			// Register storage keeps its complete X alias, but only the
			// repeated scalar bytes are inputs. Memory reads the exact tuple.
			source.width, source.requiredBytes = 16, x86CallerVectorByteMask(int64(form.sourceBytes))
		}
		return x86TypedByteEffect{
			vector: x86TypedVectorEffect{x86TypedVectorUpperZero, 1},
			operands: []x86TypedByteOperand{
				source,
				{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true},
			},
		}, true, nil
	}
	return x86TypedByteEffect{}, false, nil
}

func x86BlockTransferDependencyEffect(ins Instr, form x86InsertExtractForm) x86TypedByteEffect {
	inputBytes, baseBytes := form.blockInputBytes()
	width := form.width
	if form.spec.insert {
		width = form.spec.chunk
	}
	source := x86TypedByteOperand{index: form.source, operand: ins.Args[form.source], width: int64(width), read: true}
	if source.operand.Kind == OpReg {
		source.requiredBytes = inputBytes
	}
	effect := x86TypedByteEffect{
		vector:   x86TypedVectorEffect{x86TypedVectorUpperZero, 1},
		operands: make([]x86TypedByteOperand, 0, 3),
	}
	effect.operands = append(effect.operands, source)
	if form.spec.insert {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.base, operand: ins.Args[form.base], width: int64(form.width), read: true, requiredBytes: baseBytes,
		})
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{
		index: form.destination, operand: ins.Args[form.destination], width: int64(form.output), write: true,
	})
	return effect
}

// VEX has only the low physical X/Y bank. This check does not infer an
// encoding from the opcode prefix: opcode-specific EVEX-only forms are also
// excluded by the validated family descriptor passed by each adapter.
func x86LowVEXVectorOperands(ins Instr) bool {
	for _, operand := range ins.Args {
		if operand.Kind != OpReg {
			continue
		}
		width := amd64VectorByteWidth(operand.Reg)
		if width > 32 || !amd64VEXVectorRegister(operand, width) {
			return false
		}
	}
	return true
}

func x86UnmaskedVEXBinaryEffect(ins Instr, form x86PackedBinaryForm, vex bool, err error) (x86TypedByteEffect, bool, error) {
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	if !vex || form.legacy || form.mmx || form.mask >= 0 || form.broadcast || form.zeroing || !x86LowVEXVectorOperands(ins) {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("vector effect requires its separate non-VEX consumer: %s", ins.Op)
	}
	return x86PackedBinaryDependencyEffect(ins, form, ins.Args[form.first]), true, nil
}

func x86UnmaskedVEXShiftEffect(ins Instr, form x86PackedShiftForm, err error) (x86TypedByteEffect, bool, error) {
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	// The grammar's numerical dimensions distinguish VEX from the EVEX-only
	// word-per-lane and arithmetic-qword forms without a second opcode list.
	if form.legacy || form.mmx || form.mask >= 0 || form.broadcast || form.zeroing || !x86LowVEXVectorOperands(ins) ||
		form.arithmetic && form.laneBits == 64 || form.countMode == x86PackedShiftPerLane && form.laneBits == 16 ||
		form.countOperand.Kind == OpImm && form.memory == form.data {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("shift effect requires its separate non-VEX consumer: %s", ins.Op)
	}
	return x86PackedShiftDependencyEffect(ins, form), true, nil
}

// Numerical register dependencies and native access widths are separate axes.
// Reuse the result model for the union of bytes needed by every output byte;
// a uniform register count ignores its upper qword, but memory still reads m128.
func x86PackedShiftDependencyEffect(ins Instr, form x86PackedShiftForm) x86TypedByteEffect {
	width, countWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.countOperand.Kind == OpImm {
		countWidth = 1
	} else if form.countMode == x86PackedShiftUniform {
		countWidth = 16 // The full m128 access is observable, not just its low qword.
	}
	var dataBytes, countBytes uint64
	for output := 0; output < form.byteWidth; output++ {
		data, count := x86PackedShiftByteInputs(form, output)
		dataBytes, countBytes = dataBytes|data, countBytes|count
	}
	vector := x86TypedVectorEffect{x86TypedVectorUpperZero, 1}
	if form.legacy {
		vector = x86TypedVectorEffect{x86TypedVectorUpperPreserve, 16}
	}
	effect := x86TypedByteEffect{
		vector: vector,
		operands: []x86TypedByteOperand{
			{index: form.count, operand: form.countOperand, width: countWidth, read: true},
			{index: form.data, operand: ins.Args[form.data], width: width, read: dataBytes != 0 || ins.Args[form.data].Kind != OpReg},
			{index: form.destination, operand: ins.Args[form.destination], width: width, write: true},
		},
	}
	if form.countOperand.Kind == OpReg {
		effect.operands[0].requiredBytes = countBytes
	}
	if ins.Args[form.data].Kind == OpReg {
		effect.operands[1].requiredBytes = dataBytes
	}
	return effect
}
