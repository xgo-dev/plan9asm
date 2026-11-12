package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedSubtractMode = x86PackedArithmeticMode

const (
	amd64PackedSubtractWrap               = x86PackedWrap
	amd64PackedSubtractSignedSaturating   = x86PackedSignedSaturating
	amd64PackedSubtractUnsignedSaturating = x86PackedUnsignedSaturating
)

// lowerPackedIntegerSubtract implements the complete Go 1.27 packed-integer
// subtract family: legacy yxm XMM forms and the shared _yvandnpd VEX/EVEX
// forms. Go's 386 frontend accepts low-bank X/Y/Z three-operand forms but
// rejects explicit source masks; high banks retain their physical Context.
func (c *amd64Ctx) lowerPackedIntegerSubtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, _, _, known := amd64PackedSubtractProperties(base); !known {
		return false, false, nil
	}
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != strings.ToUpper(string(op)) {
		return true, false, fmt.Errorf("packed subtract dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86PackedSubtractProperties(ins, c.goarch)
	if err != nil || !known {
		return known, false, err
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !c.nativeMemoryOperand(ins, form.first)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed subtract needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.laneBits
	mnemonic := ""
	if form.legacy && form.memory >= 0 {
		mnemonic = strings.ToLower(base)
		if base == "PSUBL" {
			mnemonic = "psubd"
		}
	}
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, bits, mnemonic,
		func(lanes, bits int, first, second string) string {
			return c.emitPackedIntegerSubtract(lanes, bits, first, second, form.mode)
		})
	return true, false, err
}

func amd64PackedSubtractProperties(op string) (int, amd64PackedSubtractMode, bool, bool) {
	spec, known := x86PackedArithmeticSpecs[Op(op)]
	if !known || spec.family != x86PackedArithmeticSubtract {
		return 0, 0, false, false
	}
	return spec.laneBits, spec.mode, spec.encoding == x86PackedLogicalVEXOrEVEX, true
}

// emitPackedIntegerSubtract computes second-first, matching Go assembler's
// rm,v,destination operand order.
func (c *amd64Ctx) emitPackedIntegerSubtract(lanes, laneBits int, first, second string, mode amd64PackedSubtractMode) string {
	vecType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	if mode == amd64PackedSubtractWrap {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", result, vecType, second, first)
		return "%" + result
	}

	wideBits := laneBits * 2
	wideType := fmt.Sprintf("<%d x i%d>", lanes, wideBits)
	extend := "sext"
	if mode == amd64PackedSubtractUnsignedSaturating {
		extend = "zext"
	}
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", firstWide, extend, vecType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", secondWide, extend, vecType, second, wideType)
	difference := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %%%s\n", difference, wideType, secondWide, firstWide)

	clamped := "%" + difference
	minValue := int64(0)
	if mode == amd64PackedSubtractSignedSaturating {
		minValue = -int64(uint64(1) << (laneBits - 1))
	}
	below := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", below, wideType, clamped, llvmSplatSignedInteger(lanes, wideBits, minValue))
	boundedBelow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", boundedBelow, lanes, below, wideType, llvmSplatSignedInteger(lanes, wideBits, minValue), wideType, clamped)
	clamped = "%" + boundedBelow
	if mode == amd64PackedSubtractSignedSaturating {
		maxValue := int64((uint64(1) << (laneBits - 1)) - 1)
		above := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp sgt %s %s, %s\n", above, wideType, clamped, llvmSplatSignedInteger(lanes, wideBits, maxValue))
		boundedAbove := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", boundedAbove, lanes, above, wideType, llvmSplatSignedInteger(lanes, wideBits, maxValue), wideType, clamped)
		clamped = "%" + boundedAbove
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, wideType, clamped, vecType)
	return "%" + result
}
