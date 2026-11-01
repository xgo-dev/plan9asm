package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerPackedLowMultiply(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86PackedLowMultiplyProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed low multiply m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.spec.laneBits
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, bits, "pmulld",
		func(lanes, bits int, first, second string) string {
			product := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul <%d x i%d> %s, %s\n", product, lanes, bits, second, first)
			return "%" + product
		})
	return true, false, err
}

func isAMD64MemoryOperand(op Operand) bool {
	switch op.Kind {
	case OpFP, OpMem:
		return true
	case OpSym:
		// Go TYPE_ADDR is an address, not a TYPE_MEM read.
		return !strings.HasPrefix(strings.TrimSpace(op.Sym), "$")
	default:
		return false
	}
}
