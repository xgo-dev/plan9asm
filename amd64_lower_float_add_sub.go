package plan9asm

import (
	"fmt"
)

func (c *amd64Ctx) lowerFloatAddSub(op Op, ins Instr) (bool, bool, error) {
	return c.lowerFloatArithmetic(op, ins, x86FloatAddSubtract)
}

func (c *amd64Ctx) lowerFloatAddSubForm(ins Instr, form x86FloatAddSubForm) (bool, bool, error) {
	return c.lowerFloatBinaryOperands(ins, form.x86FloatBinaryForm, func(lanes int, left, right, mask string) string {
		return c.emitFloatAddSub(form, lanes, left, right, mask)
	})
}

// Shared yxm/VEX/EVEX source loading and alias writes. Each family supplies
// its arithmetic emitter, so a common shape grants no numerical behavior.
func (c *amd64Ctx) lowerFloatBinaryOperands(ins Instr, form x86FloatBinaryForm, emit func(int, string, string, string) string) (bool, bool, error) {
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.scalar && form.memory >= 0 {
		return true, false, c.lowerLegacyPackedFloatingMemory(ins, form)
	}
	if first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	var mask string
	var err error
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	bits := form.bits
	if form.scalar {
		var a string
		var err error
		if form.literal {
			if bits == 32 {
				a, err = c.evalF32(first)
			} else {
				a, err = c.evalF64(first)
			}
		} else {
			a, err = c.loadFloatBinaryScalar(first, bits, mask)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadFMA3Scalar(second, bits, "")
		if err != nil {
			return true, false, err
		}
		value := emit(1, b, a, mask)
		integer := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", integer, amd64FMA3LLVMType(1, bits), value, bits)
		upper, err := c.loadX(second.Reg)
		if err != nil {
			return true, false, err
		}
		lanes := 128 / bits
		base := c.bitcastVectorBytesToIntegerLanes(16, lanes, bits, upper)
		if !form.legacy {
			return true, false, c.storeScalarMoveRegister(destination.Reg, bits, "%"+integer, base, mask, form.zeroing)
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 0\n", merged, lanes, bits, base, bits, integer)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytes, lanes, bits, merged)
		return true, false, c.storeLegacyPackedLogical(destination, "%"+bytes)
	}
	lanes := form.byteWidth * 8 / bits
	a, err := c.loadFloatBinaryPacked(first, form.byteWidth, bits, form.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	b, err := c.loadPackedCompareLanes(second, form.byteWidth, bits, false)
	if err != nil {
		return true, false, err
	}
	floatType := amd64FMA3LLVMType(lanes, bits)
	aFloat, bFloat := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to %s\n", aFloat, lanes, bits, a, floatType)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to %s\n", bFloat, lanes, bits, b, floatType)
	value := emit(lanes, "%"+bFloat, "%"+aFloat, mask)
	result := c.bitcastFloatingToIntegerLanes(floatType, lanes, bits, value)
	if form.mask >= 0 {
		old, err := c.loadPackedCompareLanes(destination, form.byteWidth, bits, false)
		if err != nil {
			return true, false, err
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, bits, result, old, mask, form.zeroing)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, bits, result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(destination, "%"+bytes)
	}
	return true, false, c.storePackedMoveOperand(destination, form.byteWidth, "%"+bytes)
}

func (c *amd64Ctx) emitFloatAddSub(form x86FloatAddSubForm, lanes int, left, right, mask string) string {
	if form.rounding != "" {
		return c.emitRoundedFloatAddSub(lanes, form.spec.bits, left, right, (form.spec.mode == amd64BinaryFloatingSub), form.rounding)
	}
	// Do not grant fast-math, reassociation or an ambient-rounding assumption.
	// Dynamic strict operations retain x86 rounding/DAZ/FTZ/exception behavior.
	operation := "fadd"
	if form.spec.mode == amd64BinaryFloatingSub {
		operation = "fsub"
	}
	return c.emitStrictFloatBinary(form.x86FloatBinaryForm, operation, lanes, left, right, mask, func(lanes int, left, right, value string) string {
		return c.emitFloatAddSubSpecial(form.spec.bits, lanes, left, right, (form.spec.mode == amd64BinaryFloatingSub), value)
	})
}

// Strict operations must remain observable under middle-end optimization.
// The correction callback handles each family's native NaN result priority
// without replacing the actual hardware rounding or exception side effects.
func (c *amd64Ctx) emitStrictFloatBinary(form x86FloatBinaryForm, operation string, lanes int, left, right, mask string, correct func(int, string, string, string) string) string {
	typ := amd64FMA3LLVMType(lanes, form.bits)
	if mask != "" {
		// EVEX suppresses arithmetic exceptions as well as memory faults for
		// inactive lanes. Selecting after an eager strict fadd is not enough.
		scalarType := amd64FMA3LLVMType(1, form.bits)
		result := "poison"
		for lane := 0; lane < lanes; lane++ {
			values := []string{left, right}
			if lanes > 1 {
				for index, value := range values {
					extracted := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, typ, value, lane)
					values[index] = "%" + extracted
				}
			}
			active := amd64MaskBitI1(c, mask, lane)
			integer, _ := c.loadX86ScalarIf(form.bits, active, func() (string, error) {
				value, bits := c.newTmp(), c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.experimental.constrained.%s.f%d(%s %s, %s %s, metadata !\"round.dynamic\", metadata !\"fpexcept.strict\")\n", value, scalarType, operation, form.bits, scalarType, values[0], scalarType, values[1])
				corrected := correct(1, values[0], values[1], "%"+value)
				fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", bits, scalarType, corrected, form.bits)
				return "%" + bits, nil
			})
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to %s\n", value, form.bits, integer, scalarType)
			if lanes == 1 {
				return "%" + value
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typ, result, scalarType, value, lane)
			result = "%" + inserted
		}
		return result
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.experimental.constrained.%s.%s(%s %s, %s %s, metadata !\"round.dynamic\", metadata !\"fpexcept.strict\")\n", result, typ, operation, amd64BinaryFloatingIntrinsicSuffix(lanes, form.bits), typ, left, typ, right)
	return correct(lanes, left, right, "%"+result)
}

// LLVM's commutative add legalization can swap NaN operands even for a
// constrained operation. Preserve its real hardware exception/rounding
// effects, but restore x86 binary source-order payload/indefinite results.
func (c *amd64Ctx) emitFloatAddSubSpecial(bits, lanes int, left, right string, subtract bool, hardware string) string {
	scalarType, typ := amd64FMA3LLVMType(1, bits), amd64FMA3LLVMType(lanes, bits)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		values := []string{left, right, hardware}
		if lanes > 1 {
			for index, value := range values {
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, typ, value, lane)
				values[index] = "%" + extracted
			}
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @__plan9asm_add_sub_special_f%d(%s %s, %s %s, i1 %t, %s %s)\n", value, scalarType, bits, scalarType, values[0], scalarType, values[1], subtract, scalarType, values[2])
		if lanes == 1 {
			return "%" + value
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, typ, result, scalarType, value, lane)
		result = "%" + inserted
	}
	return result
}
