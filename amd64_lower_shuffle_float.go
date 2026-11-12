package plan9asm

import "fmt"

// Every consumer shares the complete Go grammar and exact two-source selector.
// Integer byte lanes preserve NaN payloads without creating FP/MXCSR effects.
func (c *amd64Ctx) lowerPackedFloatShuffle(op Op, ins Instr) (bool, bool, error) {
	f, known, err := x86PackedFloatShuffleProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, f.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	first, second, destination := ins.Args[f.first], ins.Args[f.second], ins.Args[f.destination]
	secondBytes, err := c.loadPackedCompareBytes(second, f.byteWidth)
	if err != nil {
		return true, false, err
	}
	if f.legacy && f.memory >= 0 {
		if first.Kind == OpFP || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
			return true, false, fmt.Errorf("%w: legacy floating shuffle m128 needs its original native storage/target", ErrProbeNeedsContext)
		}
		lanes := c.bitcastVectorBytesToIntegerLanes(16, 128/f.bits, f.bits, secondBytes)
		mnemonic := "shufps"
		if f.bits == 64 {
			mnemonic = "shufpd"
		}
		// Keep the complete original Type4 opcode and its RMW destination:
		// align-1 loads do not reproduce legacy m128 alignment exceptions.
		value, err := c.emitPackedBinaryNativeMemory(first, f.bits, lanes,
			fmt.Sprintf("%s $$%d,", mnemonic, f.selector))
		if err != nil {
			return true, false, err
		}
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", bytes, 128/f.bits, f.bits, value)
		return true, false, c.storeLegacyPackedLogical(destination, "%"+bytes)
	}
	readWidth := f.byteWidth
	if f.memory >= 0 {
		readWidth = f.memoryBytes
	}
	// EVEX E4NF does not suppress faults. Even a zero mask, selected scalar
	// or dead result retains this single full/broadcast unaligned read.
	firstBytes, err := c.loadX86PackedShiftBytes(first, readWidth, true)
	if err != nil {
		return true, false, err
	}
	indices := make([]int, f.byteWidth)
	width := f.byteWidth
	if f.broadcast {
		// Extend only the representation to a common shufflevector width;
		// no additional memory byte or initialized input is introduced.
		expanded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> %s\n",
			expanded, readWidth, firstBytes, readWidth, width, llvmRepeatI8Mask(readWidth, width))
		firstBytes = "%" + expanded
	}
	for output := range indices {
		indices[output] = f.sourceByte(output)
	}
	shuffled := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n",
		shuffled, width, firstBytes, width, secondBytes, width, llvmI32Mask(indices))
	result := "%" + shuffled
	if f.mask >= 0 {
		mask, err := c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
		lanes := width * 8 / f.bits
		computed := c.bitcastVectorBytesToIntegerLanes(width, lanes, f.bits, result)
		old := "zeroinitializer"
		if !f.zeroing {
			old, err = c.loadPackedCompareLanes(destination, width, f.bits, false)
			if err != nil {
				return true, false, err
			}
		}
		masked := amd64ApplyIntegerLaneMask(c, lanes, f.bits, computed, old, mask, f.zeroing)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, f.bits, masked, width)
		result = "%" + bytes
	}
	if f.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, result)
	}
	return true, false, c.storePackedMoveOperand(destination, width, result)
}

func amd64PackedFloatShuffleProperties(op string) (laneBits int, vector, ok bool) {
	switch op {
	case "SHUFPS":
		return 32, false, true
	case "SHUFPD":
		return 64, false, true
	case "VSHUFPS":
		return 32, true, true
	case "VSHUFPD":
		return 64, true, true
	default:
		return 0, false, false
	}
}

func amd64UnsignedImm8(arg Operand) (uint8, bool) {
	if arg.Kind != OpImm || arg.Imm < 0 || arg.Imm > 255 {
		return 0, false
	}
	return uint8(arg.Imm), true
}
