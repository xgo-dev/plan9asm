package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerPackedLogicalFamily(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, recognized := x86PackedLogicalSpecs[Op(base)]; !recognized {
		return false, false, nil
	}
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != strings.ToUpper(string(op)) {
		return true, false, fmt.Errorf("packed logical dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, recognized, err := x86PackedLogicalProperties(ins, c.goarch)
	if err != nil || !recognized {
		return recognized, false, err
	}
	if err := x86LegacyMMXReadEmitterContext(ins, c.goarch); err != nil {
		return true, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return true, false, fmt.Errorf("%w: legacy packed logical m128 lacks original native address-size binding", ErrProbeNeedsContext)
		}
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed logical m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.mmx {
		a, err := c.evalIntSized(first, I64)
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		if form.spec.mode == amd64PackedLogicalAndNot {
			inverted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, -1\n", inverted, b)
			b = "%" + inverted
		}
		operation := "and"
		if form.spec.mode == amd64PackedLogicalOr {
			operation = "or"
		}
		if form.spec.mode == amd64PackedLogicalXor {
			operation = "xor"
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i64 %s, %s\n", result, operation, b, a)
		return true, false, c.storeReg(destination.Reg, "%"+result)
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	lanes := form.byteWidth * 8 / form.spec.laneBits
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	b, err := c.loadPackedCompareLanes(second, form.byteWidth, form.spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	var result string
	if form.legacy && form.memory >= 0 {
		// Retain the single original memory opcode: an align-1 load and
		// portable logical arithmetic lose its alignment/dead-read faults.
		result, err = c.emitPackedBinaryNativeMemory(first, form.spec.laneBits, b, strings.ToLower(string(op)))
	} else {
		// Native reads remain observable with dead results. EVEX inactive
		// lanes alone suppress their accesses, including scalar broadcasts.
		var a string
		if ins.x86NumericalRead != nil || c.goReadOnlyOperand.allows(first, int64(form.memoryBytes)) ||
			first.Kind == OpMem && x86OrdinaryNativeMemoryOperand(first, c.goarch) {
			a, err = c.loadX86PackedShiftLanes(first, form.byteWidth, form.spec.laneBits, form.broadcast, mask)
		} else {
			a, err = c.loadMaskedPackedCompareLanes(first, form.byteWidth, form.spec.laneBits, form.broadcast, mask)
		}
		if err == nil {
			result = c.emitPackedLogical(lanes, amd64PackedLogicalSpec{form.spec.laneBits, form.spec.mode}, a, b)
		}
	}
	if err != nil {
		return true, false, err
	}
	if form.mask >= 0 {
		old, err := c.loadPackedCompareLanes(destination, form.byteWidth, form.spec.laneBits, false)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, form.spec.laneBits, result, old, mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, form.spec.laneBits, result, form.byteWidth)
	if form.legacy {
		// Legacy writes update low X bits in every wider view but preserve the
		// upper bytes. storeX alone is a separate shadow slot, not an alias.
		return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) storeLegacyPackedLogical(dst Operand, value string) error {
	index, _ := amd64ParseXReg(dst.Reg)
	for _, view := range []struct {
		width int
		slots map[int]string
	}{{32, c.yRegSlot}, {64, c.zRegSlot}} {
		slot, live := view.slots[index]
		if !live {
			continue
		}
		old, merged := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <%d x i8>, ptr %s\n", old, view.width, slot)
		extended := c.newTmp()
		extendIndices := make([]string, view.width)
		for i := range extendIndices {
			lane := i
			if i >= 16 {
				lane = 16
			}
			extendIndices[i] = fmt.Sprintf("i32 %d", lane)
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector <16 x i8> %s, <16 x i8> zeroinitializer, <%d x i32> <%s>\n", extended, value, view.width, strings.Join(extendIndices, ", "))
		indices := make([]string, view.width)
		for i := range indices {
			lane := i
			if i < 16 {
				lane += view.width
			}
			indices[i] = fmt.Sprintf("i32 %d", lane)
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %%%s, <%d x i8> %%%s, <%d x i32> <%s>\n", merged, view.width, old, view.width, extended, view.width, strings.Join(indices, ", "))
		fmt.Fprintf(c.b, "  store <%d x i8> %%%s, ptr %s\n", view.width, merged, slot)
	}
	return c.storeX(dst.Reg, value)
}
