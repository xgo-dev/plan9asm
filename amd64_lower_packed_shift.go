package plan9asm

import "fmt"

func (c *amd64Ctx) lowerX86PackedShift(op Op, ins Instr) (bool, bool, error) {
	form, recognized, err := x86PackedShiftProperties(op, ins, c.goarch)
	if !recognized || err != nil {
		return recognized, false, err
	}
	local := ins
	local.Op = op
	if err := x86LegacyMMXReadEmitterContext(local, c.goarch); err != nil {
		return true, false, err
	}
	if x86PackedShiftHasNativeCount(form) && ins.Args[form.count].Kind == OpFP {
		return true, false, fmt.Errorf("legacy m128 count needs actual native FP backing: %w", ErrProbeNeedsContext)
	}
	if form.memory >= 0 && ins.Args[form.memory].Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(ins.Args[form.memory].FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	dataArg := ins.Args[form.data]
	var data string
	if form.mmx {
		bits, err := c.loadReg(dataArg.Reg)
		if err != nil {
			return true, false, err
		}
		data = c.bitcastI64ToIntegerLanes(64/form.laneBits, form.laneBits, bits)
	} else if form.countMode == x86PackedShiftBytes {
		data, err = c.loadX86PackedShiftBytes(dataArg, form.byteWidth, true)
	} else {
		dataMask := ""
		if form.faultSuppressed && form.memory == form.data {
			dataMask = mask
		}
		if form.memory == form.data && !form.faultSuppressed {
			bytes, loadErr := c.loadX86PackedShiftBytes(dataArg, form.byteWidth, true)
			err = loadErr
			if err == nil {
				data = c.bitcastVectorBytesToIntegerLanes(form.byteWidth, form.byteWidth*8/form.laneBits, form.laneBits, bytes)
			}
		} else {
			data, err = c.loadX86PackedShiftLanes(dataArg, form.byteWidth, form.laneBits, form.broadcast && form.memory == form.data, dataMask)
		}
	}
	if err != nil {
		return true, false, err
	}
	lanes := form.byteWidth * 8 / form.laneBits
	var result string
	if form.countMode == x86PackedShiftBytes {
		result = c.emitPackedByteShift(form.byteWidth, data, uint8(form.countOperand.Imm), form.left)
	} else {
		if form.countMode == x86PackedShiftPerLane {
			counts, err := c.loadX86PackedShiftLanes(ins.Args[form.count], form.byteWidth, form.laneBits, form.broadcast, mask)
			if err != nil {
				return true, false, err
			}
			operation := "lshr"
			if form.left {
				operation = "shl"
			} else if form.arithmetic {
				operation = "ashr"
			}
			result = c.emitPerLaneVariableShift(amd64PerLaneVariableShiftSpec{
				laneBits: form.laneBits, operation: operation, arithmetic: form.arithmetic,
			}, lanes, counts, data)
		} else if x86PackedShiftHasNativeCount(form) {
			result, err = c.emitX86PackedShiftNativeCount(form, ins.Args[form.count], data)
			if err != nil {
				return true, false, err
			}
		} else {
			count, err := c.loadPackedUniformLogicalShiftCount(form.countOperand, form.mmx)
			if err != nil {
				return true, false, err
			}
			if form.arithmetic {
				result = c.emitPackedArithmeticRightShift(lanes, form.laneBits, data, count)
			} else {
				result = c.emitPackedLogicalShift(amd64PackedLogicalShiftSpec{laneBits: form.laneBits, left: form.left}, lanes, data, count)
			}
		}
		if form.mask >= 0 {
			old, err := c.loadPackedCompareLanes(ins.Args[form.destination], form.byteWidth, form.laneBits, false)
			if err != nil {
				return true, false, err
			}
			result = amd64ApplyIntegerLaneMask(c, lanes, form.laneBits, result, old, mask, form.zeroing)
		}
		out := c.newTmp()
		if form.mmx {
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", out, lanes, form.laneBits, result)
			return true, false, c.storeReg(ins.Args[form.destination].Reg, "%"+out)
		}
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.laneBits, result, form.byteWidth)
		result = "%" + out
	}
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(ins.Args[form.destination], result)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, result)
}

// Native reads remain observable even when the shift result is a known zero.
// Only actual EVEX mask bits can suppress the corresponding memory accesses;
// LLVM dead-value elimination is not a native fault-suppression contract.
func (c *amd64Ctx) loadX86PackedShiftLanes(source Operand, width, bits int, broadcast bool, mask string) (string, error) {
	if source.Kind != OpMem && source.Kind != OpSym && source.Kind != OpFP {
		return c.loadMaskedPackedCompareLanes(source, width, bits, broadcast, mask)
	}
	lanes := width * 8 / bits
	if mask == "" {
		bytes := width
		if broadcast {
			bytes = bits / 8
		}
		value, err := c.loadX86PackedShiftBytes(source, bytes, true)
		if err != nil {
			return "", err
		}
		if !broadcast {
			return c.bitcastVectorBytesToIntegerLanes(width, lanes, bits, value), nil
		}
		scalar := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", scalar, bytes, value, bits)
		return amd64SplatInteger(c, lanes, bits, "%"+scalar), nil
	}
	load := func(offset int) func() (string, error) {
		return func() (string, error) {
			operand := source
			if operand.Kind == OpFP {
				operand.FPOffset += int64(offset)
				bytes, err := c.loadX86PackedShiftBytes(operand, bits/8, true)
				if err != nil {
					return "", err
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to i%d\n", value, bits/8, bytes, bits)
				return "%" + value, nil
			}
			pointer, pointerType, _, err := c.packedVectorMemoryPointer(operand)
			if err != nil {
				return "", err
			}
			at, value := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %d\n", at, pointerType, pointer, offset)
			fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %%%s, align 1\n", value, bits, pointerType, at)
			return "%" + value, nil
		}
	}
	if broadcast {
		relevant, active := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
		value, err := c.loadX86ScalarIf(bits, "%"+active, load(0))
		if err != nil {
			return "", err
		}
		return amd64SplatInteger(c, lanes, bits, value), nil
	}
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		selected, active := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", selected, mask, uint64(1)<<uint(lane))
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, selected)
		value, err := c.loadX86ScalarIf(bits, "%"+active, load(lane*bits/8))
		if err != nil {
			return "", err
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, lanes, bits, result, bits, value, lane)
		result = "%" + inserted
	}
	return result, nil
}

func (c *amd64Ctx) loadX86PackedShiftBytes(source Operand, width int, observable bool) (string, error) {
	if source.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(source.FPOffset, width); err != nil {
			return "", err
		}
		if c.classicFrame == "" {
			// Every native ABI0 byte is bound; preserve its little-endian
			// value without pretending independent allocas are contiguous.
			return c.loadFPVectorBytes(source.FPOffset, width)
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, ptr %s, align 1\n",
			value, width, c.classicFramePtr(source.FPOffset))
		return "%" + value, nil
	}
	if !observable || source.Kind != OpMem && source.Kind != OpSym {
		return c.loadPackedCompareBytes(source, width)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile <%d x i8>, %s %s, align 1\n", value, width, pointerType, pointer)
	return "%" + value, nil
}
