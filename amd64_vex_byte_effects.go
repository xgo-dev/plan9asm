package plan9asm

import "strings"

// Each participating family projects VEX and EVEX forms from its typed
// operands. Families with a narrower fixed-local contract validate it here.
func x86VectorDependencyByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !strings.HasPrefix(strings.ToUpper(string(op)), "V") {
		return x86TypedByteEffect{}, false, nil
	}
	if form, known, err := x86PackedArithmeticProperties(ins.Op, ins, arch, x86PackedArithmeticAdd|x86PackedArithmeticSubtract); known {
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
	}
	if form, known, err := x86PackedBinaryEffectProperties(op, ins, arch); known {
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
	}
	if form, known, err := x86IntegerMinMaxProperties(op, ins, arch); known {
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
	}
	if form, known, err := x86PackedLogicalProperties(ins, arch); known {
		effect, known, err := x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
		if err == nil {
			effect = x86PackedLogicalZeroDependencies(ins, form, effect)
		}
		return effect, known, err
	}
	if form, known, err := x86ByteShuffleProperties(op, ins, arch); known {
		return x86UnmaskedVEXBinaryEffect(ins, form, true, err)
	}
	if form, known, err := x86GFNIProperties(op, ins, arch); known {
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
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
		if form.undefinedOpcode() {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("zeroing masked extract to memory has no continuation: %s", ins.Op)
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
		if form.spec.legacy || form.spec.mmx {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("shuffle effect requires a vector-encoded result: %s", ins.Op)
		}
		return x86ImmediateShuffleDependencyEffect(ins, form), true, nil
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
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if form.legacy || form.mmx {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("packed shift needs a VEX/EVEX vector result: %s", ins.Op)
		}
		return x86PackedShiftDependencyEffect(ins, form), true, nil
	}
	if form, known, err := x86BroadcastProperties(op, ins, arch); known {
		if err != nil {
			return x86TypedByteEffect{}, true, err
		}
		if ins.Args[0].Kind == OpImm {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("broadcast immediate requires its original raw source: %s", ins.Op)
		}
		source := x86TypedByteOperand{index: 0, operand: ins.Args[0], width: int64(form.sourceBytes), read: true}
		switch {
		case form.kind == x86BroadcastMask:
			source.width = 8 // The complete defined K container supplies its low scalar bits.
		case source.operand.Kind == OpReg && amd64VectorByteWidth(source.operand.Reg) != 0:
			// Keep the X alias and require only the repeated source bytes.
			source.width, source.requiredBytes = 16, x86CallerVectorByteMask(int64(form.sourceBytes))
		case source.operand.Kind == OpReg:
			source.numericalGP = true
		}
		effect := x86TypedByteEffect{
			vector: x86TypedVectorEffect{x86TypedVectorUpperZero, 1},
			operands: []x86TypedByteOperand{
				source,
				{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth), write: true},
			},
		}
		effect.addWritemask(ins, form.mask, form.zeroing)
		return effect, true, nil
	}
	if effect, known, err := x86TypedCompactExpandByteEffect(op, ins, arch); known {
		// The frame proof checks the full possible span. Each compact
		// prefix stays within that span, independent of the mask value.
		effect.dynamicMemory = false
		return effect, true, err
	}
	if form, known, err := x86PackedUnpackProperties(local, arch); known {
		if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("packed unpack dispatch/source mismatch: %s/%s", op, ins.Op)
		}
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
	}
	if form, known, err := x86PackedNarrowProperties(local, arch); known {
		if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
			return x86TypedByteEffect{}, true, goAMD64FrameContext("packed narrow dispatch/source mismatch: %s/%s", op, ins.Op)
		}
		return x86VectorBinaryDependencyEffect(ins, form.x86PackedBinaryForm, err)
	}
	for _, project := range [...]func(Op, Instr, string) (x86TypedByteEffect, bool, error){
		x86TypedPackedRotateByteEffect,
		x86TypedElementPermuteByteEffect,
		x86TypedShuffle128BitBlocksByteEffect,
		x86TypedMaskBlendByteEffect,
		x86TypedPackedExtendByteEffect,
		x86TypedSingleSourceNarrowByteEffect,
		x86TypedPackedAlignByteEffect,
		x86TypedConflictFunnelByteEffect,
		x86TypedPackedBitCountByteEffect,
		x86TypedIndexedPermuteByteEffect,
		x86TypedQwordLookupByteEffect,
		x86TypedIFMAByteEffect,
		x86TypedPackedTestMaskByteEffect,
		x86TypedFloatCompareMaskByteEffect,
		x86TypedFMA3ByteEffect,
		x86TypedFloatArithmeticByteEffect,
	} {
		if effect, known, err := project(op, ins, arch); known {
			return effect, true, err
		}
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
	capacity := 3
	if form.spec.insert && form.mask >= 0 {
		capacity++
	}
	effect := x86TypedByteEffect{
		vector:   x86TypedVectorEffect{x86TypedVectorUpperZero, 1},
		operands: make([]x86TypedByteOperand, 0, capacity),
	}
	effect.operands = append(effect.operands, source)
	if form.spec.insert {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.base, operand: ins.Args[form.base], width: int64(form.width), read: true, requiredBytes: baseBytes,
		})
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{
		index: form.destination, operand: ins.Args[form.destination], width: int64(form.output), write: true,
		partialWrite: form.memoryWrite && form.mask >= 0,
	})
	// A masked store preserves inactive memory without reading it.
	effect.addWritemask(ins, form.mask, form.zeroing || form.memoryWrite)
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
	if err == nil && (!vex || form.mask >= 0 || form.broadcast || form.zeroing || !x86LowVEXVectorOperands(ins)) {
		err = goAMD64FrameContext("vector effect requires its separate non-VEX consumer: %s", ins.Op)
	}
	return x86VectorBinaryDependencyEffect(ins, form, err)
}

func x86VectorBinaryDependencyEffect(ins Instr, form x86PackedBinaryForm, err error) (x86TypedByteEffect, bool, error) {
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	if form.legacy || form.mmx {
		return x86TypedByteEffect{}, true, goAMD64FrameContext("packed binary instruction needs a VEX/EVEX vector result: %s", ins.Op)
	}
	return x86PackedBinaryDependencyEffect(ins, form, ins.Args[form.first]), true, nil
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
	dataWidth := width
	switch form.memory {
	case form.count:
		countWidth = int64(form.memoryBytes)
	case form.data:
		dataWidth = int64(form.memoryBytes)
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
			{index: form.data, operand: ins.Args[form.data], width: dataWidth, read: dataBytes != 0 || ins.Args[form.data].Kind != OpReg},
			{index: form.destination, operand: ins.Args[form.destination], width: width, write: true},
		},
	}
	if form.countOperand.Kind == OpReg {
		effect.operands[0].requiredBytes = countBytes
	}
	if ins.Args[form.data].Kind == OpReg {
		effect.operands[1].requiredBytes = dataBytes
	}
	effect.addWritemask(ins, form.mask, form.zeroing)
	return effect
}
