package plan9asm

import "fmt"

// Only a separately closed direct-tail graph may group these logical result
// fields. This layout query grants no initialization or source permission;
// the complete graph/byte proof must succeed before the emitter uses it.
// Contiguous numeric fields get matching backing, never parameter bytes,
// pointers, bools, padding or a neighboring allocation.
func x86DirectTailResultRegion(fn Func, sig FuncSig, arch string) (x86ResultSlotAddress, bool) {
	if fn.x86DirectTailRoot == nil || arch != "amd64" && arch != "386" ||
		len(sig.Frame.Results) < 2 || len(sig.Frame.Results) > 4096 {
		return x86ResultSlotAddress{}, false
	}
	fields, valid := parseLiteralStructFields(sig.Ret)
	if !valid || len(fields) != len(sig.Frame.Results) {
		return x86ResultSlotAddress{}, false
	}
	start := sig.Frame.Results[0].Offset
	end := start
	for index, slot := range sig.Frame.Results {
		width := x86ResultScalarBytes(slot.Type, arch)
		if !x86IntegerResultSlot(slot) || slot.Type != fields[index] || slot.Index != index ||
			slot.Field != -1 || len(slot.Fields) != 0 || slot.Offset != end ||
			width <= 0 || slot.Offset < 0 || slot.Offset > 4096-width || (slot.Offset-start)%width != 0 {
			return x86ResultSlotAddress{}, false
		}
		end += width
	}
	return x86ResultSlotAddress{start: start, end: end, offset: start, valid: true}, true
}

func (c *amd64Ctx) emitDirectTailResultRegion(region x86ResultSlotAddress) {
	width := region.end - region.start
	name := "%fp_result_region"
	fmt.Fprintf(c.b, "  %s = alloca [%d x i8], align 8\n", name, width)
	for _, slot := range c.fpResults {
		pointer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr inbounds [%d x i8], ptr %s, i32 0, i64 %d\n",
			pointer, width, name, slot.Offset-region.start)
		c.fpResAllocaIdx[slot.Index] = "%" + pointer
		c.fpResAllocaOff[slot.Offset] = "%" + pointer
		c.storeFPStorage(slot.Type, llvmZeroValue(slot.Type), "%"+pointer, ", align 1", "")
	}
}
