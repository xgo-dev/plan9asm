package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedNarrowMode uint8

const (
	amd64PackedNarrowSigned amd64PackedNarrowMode = iota
	amd64PackedNarrowUnsigned
)

// All legacy/VEX/EVEX forms share one typed grammar. Packing effects remain
// separate: clamp signed inputs, then concatenate each 128-bit source pair.
func (c *amd64Ctx) lowerPackedSaturatingNarrow(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86PackedNarrowSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("packed narrow dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86PackedNarrowProperties(ins, c.goarch)
	if err != nil || !known {
		return known, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.mmx && first.Kind == OpReg && first.Reg != form.source.Reg {
		return true, false, fmt.Errorf("%w: packed narrow GP spelling needs its physical MMX transport", ErrProbeNeedsContext)
	}
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy pack m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	inputBits, outputBits := form.spec.inputBits, form.spec.outputBits
	inputLanes := form.byteWidth * 8 / inputBits
	if form.mmx {
		var firstBits string
		if form.memory >= 0 {
			firstBits, err = c.loadPackedUnpackMMXSource(first, form.memoryBytes)
		} else {
			firstBits, err = c.loadReg(first.Reg)
		}
		if err != nil {
			return true, false, err
		}
		secondBits, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		value := c.emitPackedSaturatingNarrow(form.byteWidth, inputBits, outputBits, form.spec.mode,
			c.bitcastI64ToIntegerLanes(inputLanes, inputBits, firstBits),
			c.bitcastI64ToIntegerLanes(inputLanes, inputBits, secondBits))
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", out, 64/outputBits, outputBits, value)
		return true, false, c.storeReg(destination.Reg, "%"+out)
	}
	secondValue, err := c.loadPackedCompareLanes(second, form.byteWidth, inputBits, false)
	if err != nil {
		return true, false, err
	}
	outputLanes := form.byteWidth * 8 / outputBits
	var value string
	if form.legacy && form.memory >= 0 {
		mnemonic := strings.ToLower(base)
		if base == "PACKSSLW" {
			mnemonic = "packssdw"
		}
		// Preserve legacy native alignment/fault behavior. The native result
		// is already packed: reinterpret it, do not narrow it a second time.
		packed, loadErr := c.emitPackedBinaryNativeMemory(first, inputBits, secondValue, mnemonic)
		err = loadErr
		if err == nil {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i%d>\n", out, inputLanes, inputBits, packed, outputLanes, outputBits)
			value = "%" + out
		}
	} else {
		// Intel's E4NF/E4NF.nb pack reads the entire tuple even with a zero
		// output mask or dead result. Never pass that mask to an E4 reader.
		firstValue, loadErr := c.loadX86PackedShiftLanes(first, form.byteWidth, inputBits, form.broadcast, "")
		err = loadErr
		if err == nil {
			value = c.emitPackedSaturatingNarrow(form.byteWidth, inputBits, outputBits, form.spec.mode, firstValue, secondValue)
		}
	}
	if err != nil {
		return true, false, err
	}
	if form.mask >= 0 {
		mask, err := c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
		old := "zeroinitializer"
		if !form.zeroing {
			old, err = c.loadPackedCompareLanes(destination, form.byteWidth, outputBits, false)
			if err != nil {
				return true, false, err
			}
		}
		value = amd64ApplyIntegerLaneMask(c, outputLanes, outputBits, value, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, outputLanes, outputBits, value, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) emitPackedSaturatingNarrow(byteWidth, inputBits, outputBits int, mode amd64PackedNarrowMode, first, second string) string {
	inputLanes := byteWidth * 8 / inputBits
	outputLanes := byteWidth * 8 / outputBits
	chunkBits := 128
	if byteWidth < 16 {
		chunkBits = byteWidth * 8
	}
	inputLanesPerChunk := chunkBits / inputBits
	outputLanesPerChunk := chunkBits / outputBits
	chunks := byteWidth * 8 / chunkBits
	result := "zeroinitializer"
	for chunk := 0; chunk < chunks; chunk++ {
		for sourceHalf, source := range []string{second, first} {
			for lane := 0; lane < inputLanesPerChunk; lane++ {
				inputIndex := chunk*inputLanesPerChunk + lane
				outputIndex := chunk*outputLanesPerChunk + sourceHalf*inputLanesPerChunk + lane
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, inputLanes, inputBits, source, inputIndex)
				narrowed := c.saturatePackedInteger("%"+value, inputBits, outputBits, mode)
				inserted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, outputLanes, outputBits, result, outputBits, narrowed, outputIndex)
				result = "%" + inserted
			}
		}
	}
	return result
}

func (c *amd64Ctx) saturatePackedInteger(value string, inputBits, outputBits int, mode amd64PackedNarrowMode) string {
	minValue := -(int64(1) << (outputBits - 1))
	maxValue := (int64(1) << (outputBits - 1)) - 1
	clamped := value
	if mode == amd64PackedNarrowUnsigned {
		minValue = 0
		maxValue = (int64(1) << outputBits) - 1
		below := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, 0\n", below, inputBits, clamped)
		nonnegative := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 0, i%d %s\n", nonnegative, below, inputBits, inputBits, clamped)
		clamped = "%" + nonnegative
	}
	above := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i%d %s, %d\n", above, inputBits, clamped, maxValue)
	capped := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %s\n", capped, above, inputBits, maxValue, inputBits, clamped)
	clamped = "%" + capped
	if mode == amd64PackedNarrowSigned {
		below := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, %d\n", below, inputBits, clamped, minValue)
		floored := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %s\n", floored, below, inputBits, minValue, inputBits, clamped)
		clamped = "%" + floored
	}
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i%d %s to i%d\n", narrowed, inputBits, clamped, outputBits)
	return "%" + narrowed
}
