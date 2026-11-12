package plan9asm

import "fmt"

func x86PackedShiftHasNativeCount(form x86PackedShiftForm) bool {
	return form.legacy && !form.mmx && form.memory == form.count
}

// Preserve the original SSE2 m128 operation, including its complete native
// read and fault behavior. Substituting MOVDQA would impose its alignment
// contract on a different instruction. The tied data input, vector output
// and memory clobber keep the original operation observable without granting
// the source address any permission or claiming an alignment guarantee.
func (c *amd64Ctx) emitX86PackedShiftNativeCount(form x86PackedShiftForm, source Operand, data string) (string, error) {
	if !x86PackedShiftHasNativeCount(form) || form.byteWidth != 16 || form.countMode != x86PackedShiftUniform {
		return "", fmt.Errorf("expected legacy SSE m128 packed count form")
	}
	name := "psrl"
	if form.left {
		name = "psll"
	} else if form.arithmetic {
		name = "psra"
	}
	switch form.laneBits {
	case 16:
		name += "w"
	case 32:
		name += "d"
	case 64:
		name += "q"
	default:
		return "", fmt.Errorf("unsupported legacy packed count lane width %d", form.laneBits)
	}
	return c.emitPackedBinaryNativeMemory(source, form.laneBits, data, name)
}
