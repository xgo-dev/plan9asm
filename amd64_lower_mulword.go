package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedWordMultiplyMode uint8

const (
	amd64PackedWordMultiplyLow amd64PackedWordMultiplyMode = iota
	amd64PackedWordMultiplySignedHigh
	amd64PackedWordMultiplyUnsignedHigh
	amd64PackedWordMultiplyRoundedSignedHigh
)

func (c *amd64Ctx) lowerPackedWordMultiply(op Op, ins Instr) (bool, bool, error) {
	return c.lowerPackedPhysical(op, ins, x86PackedWordProduct)
}

func (c *amd64Ctx) lowerPackedWordMultiplyForm(op Op, ins Instr, form x86PackedPhysicalForm) (bool, bool, error) {
	first, second, destination := form.source, ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed word multiply m128 needs original native storage, not virtual FP/SP/BP", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	lanes := form.byteWidth / 2
	if form.mmx {
		// A GP source accepted through ycover encodes an MMX register; it
		// must never consume the unrelated GP shadow as its input value.
		if first.Kind == OpReg && first.Reg != ins.Args[form.first].Reg {
			return true, false, fmt.Errorf("%w: Go GP-spelled packed multiply source names the MMX bank", ErrProbeNeedsContext)
		}
		var a string
		var err error
		if first.Kind == OpReg {
			a, err = c.loadReg(first.Reg)
		} else {
			a, err = c.loadPackedUnpackMMXSource(first, 8)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		value := c.emitPackedWordMultiply(lanes, c.bitcastI64ToIntegerLanes(lanes, 16, a), c.bitcastI64ToIntegerLanes(lanes, 16, b), form.spec.mode)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to i64\n", out, lanes, value)
		return true, false, c.storeReg(destination.Reg, "%"+out)
	}
	mnemonic := ""
	if form.legacy && form.memory >= 0 {
		mnemonic = strings.ToLower(string(op))
	}
	return true, false, c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, form.spec.memoryBits,
		mnemonic, func(lanes, bits int, first, second string) string {
			return c.emitPackedWordMultiply(lanes, first, second, form.spec.mode)
		})
}

func (c *amd64Ctx) emitPackedWordMultiply(lanes int, first, second string, mode amd64PackedWordMultiplyMode) string {
	wordType := fmt.Sprintf("<%d x i16>", lanes)
	if mode == amd64PackedWordMultiplyLow {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul %s %s, %s\n", result, wordType, second, first)
		return "%" + result
	}

	wideType := fmt.Sprintf("<%d x i32>", lanes)
	extend := "sext"
	shift := int64(16)
	if mode == amd64PackedWordMultiplyUnsignedHigh {
		extend = "zext"
	}
	firstWide := c.newTmp()
	secondWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", firstWide, extend, wordType, first, wideType)
	fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", secondWide, extend, wordType, second, wideType)
	product := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = mul %s %%%s, %%%s\n", product, wideType, secondWide, firstWide)
	value := "%" + product
	if mode == amd64PackedWordMultiplyRoundedSignedHigh {
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", rounded, wideType, value, llvmSplatSignedInteger(lanes, 32, 16384))
		value = "%" + rounded
		shift = 15
	}
	shifted := c.newTmp()
	shiftOp := "ashr"
	if mode == amd64PackedWordMultiplyUnsignedHigh {
		shiftOp = "lshr"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", shifted, shiftOp, wideType, value, llvmSplatSignedInteger(lanes, 32, shift))
	value = "%" + shifted
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, wideType, value, wordType)
	return "%" + result
}
