package plan9asm

import (
	"fmt"
	"strings"
)

// Preserve the helper entry point while all dword/word/MMX siblings use one
// complete grammar. Dispatch identity cannot grant a contradictory spelling.
func (c *amd64Ctx) lowerPackedWordShuffle(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86ImmediateShuffleSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("immediate-shuffle dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86ImmediateShuffleProperties(ins, c.goarch)
	if err != nil || !known {
		return known, false, err
	}
	if err := x86LegacyMMXReadEmitterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	destination := ins.Args[form.destination]
	if form.spec.legacy && !form.spec.mmx && form.memory >= 0 {
		return true, false, c.lowerLegacyImmediateShuffleMemory(ins, form)
	}
	var source string
	if form.spec.mmx {
		source, err = c.loadPackedUnpackMMXSource(form.source, form.memoryBytes)
		if err == nil {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i64 %s to <8 x i8>\n", value, source)
			source = "%" + value
		}
	} else if form.broadcast {
		bytes, loadErr := c.loadX86PackedShiftBytes(form.source, 4, true)
		err = loadErr
		if err == nil {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i8> %s, <4 x i8> zeroinitializer, <%d x i32> %s\n",
				value, bytes, form.byteWidth, llvmRepeatI8Mask(4, form.byteWidth))
			source = "%" + value
		}
	} else {
		// E4NF/E4NF.nb does not suppress memory faults, even at K=0 or when
		// the immediate selects only one lane. Keep the full read observable.
		source, err = c.loadX86PackedShiftBytes(form.source, form.byteWidth, true)
	}
	if err != nil {
		return true, false, err
	}
	indices := make([]string, form.byteWidth)
	for index := range indices {
		// A broadcast has already expanded the m32 to full logical lanes.
		if form.broadcast {
			indices[index] = fmt.Sprintf("i32 %d", index)
		} else {
			indices[index] = fmt.Sprintf("i32 %d", form.sourceByte(index))
		}
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> zeroinitializer, <%d x i32> <%s>\n",
		value, form.byteWidth, source, form.byteWidth, form.byteWidth, strings.Join(indices, ", "))
	result := "%" + value
	if form.spec.mmx {
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i8> %s to i64\n", bits, result)
		return true, false, c.storeReg(destination.Reg, "%"+bits)
	}
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		laneBits := form.spec.laneBytes * 8
		lanes := form.byteWidth / form.spec.laneBytes
		computed := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, laneBits, result)
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, laneBits, false)
			if err != nil {
				return true, false, err
			}
		}
		masked := amd64ApplyIntegerLaneMask(c, lanes, laneBits, computed, old, mask, form.zeroing)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, laneBits, masked, form.byteWidth)
		result = "%" + bytes
	}
	if form.spec.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, result)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, result)
}

func amd64PackedWordShuffleRequiresEVEX(source, destination Operand, byteWidth int, masked bool) bool {
	if byteWidth == 64 || masked {
		return true
	}
	for _, operand := range []Operand{source, destination} {
		if operand.Kind == OpReg {
			index, ok := amd64VectorRegisterIndex(operand.Reg, byteWidth)
			if !ok || index >= 16 {
				return true
			}
		}
	}
	return false
}

// Legacy m128 must retain the actual single SSE instruction's alignment and
// fault behavior, not an align-1 LLVM read or a fabricated virtual FP buffer.
func (c *amd64Ctx) lowerLegacyImmediateShuffleMemory(ins Instr, form x86ImmediateShuffleForm) error {
	source := form.source
	if source.Kind == OpFP || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		source.Kind == OpMem && !c.fixedLocalMemoryCertified(ins, form.memory) && !x86OrdinaryNativeMemoryOperand(source, c.goarch) {
		return fmt.Errorf("%w: legacy immediate shuffle m128 needs original native backing/alignment", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	mnemonic := "pshufd"
	if form.spec.laneBytes == 2 {
		mnemonic = "pshuflw"
		if form.spec.high {
			mnemonic = "pshufhw"
		}
	}
	value, bytes := c.newTmp(), c.newTmp()
	assembly := fmt.Sprintf("%s $$%d, %s($1), $0", mnemonic, form.immediate, segment)
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s %s)\n",
		value, assembly, "=x,r,~{memory}", pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, value)
	return c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+bytes)
}
