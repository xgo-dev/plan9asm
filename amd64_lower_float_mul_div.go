package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerFloatMulDiv(op Op, ins Instr) (bool, bool, error) {
	return c.lowerFloatArithmetic(op, ins, x86FloatMultiplyDivide)
}

func (c *amd64Ctx) lowerFloatMulDivForm(ins Instr, form x86FloatMulDivForm) (bool, bool, error) {
	return c.lowerFloatBinaryOperands(ins, form.x86FloatBinaryForm, func(lanes int, left, right, mask string) string {
		if form.rounding != "" {
			return c.emitRoundedFloatMulDiv(form, lanes, left, right)
		}
		operation := "fmul"
		if form.spec.mode == amd64BinaryFloatingDiv {
			operation = "fdiv"
		}
		return c.emitStrictFloatBinary(form.x86FloatBinaryForm, operation, lanes, left, right, mask, func(lanes int, left, right, value string) string {
			return c.emitFloatBinaryNaNPriority(form.bits, lanes, left, right, value)
		})
	})
}

// LLVM may commute strict multiplication during legalization. Restore x86's
// first-source NaN payload without executing another floating operation or
// changing the real strict operation's sticky/rounding/DAZ/FTZ effects.
func (c *amd64Ctx) emitFloatBinaryNaNPriority(bits, lanes int, left, right, hardware string) string {
	typ := amd64FMA3LLVMType(lanes, bits)
	integerType := fmt.Sprintf("<%d x i%d>", lanes, bits)
	if lanes == 1 {
		integerType = fmt.Sprintf("i%d", bits)
	}
	exponent, quiet := uint64(0x7f800000), uint64(0x400000)
	if bits == 64 {
		exponent, quiet = 0x7ff0000000000000, 0x8000000000000
	}
	constant := func(value uint64) string {
		if lanes == 1 {
			return fmt.Sprint(value)
		}
		values := make([]string, lanes)
		for lane := range values {
			values[lane] = fmt.Sprintf("i%d %d", bits, value)
		}
		return "<" + strings.Join(values, ", ") + ">"
	}
	values, nan, quieted := [2]string{left, right}, [2]string{}, [2]string{}
	for index, value := range values {
		raw, magnitude, isNaN, withQuiet := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", raw, typ, value, integerType)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", magnitude, integerType, raw, constant(uint64(1)<<(bits-1)-1))
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", isNaN, integerType, magnitude, constant(exponent))
		fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", withQuiet, integerType, raw, constant(quiet))
		nan[index], quieted[index] = "%"+isNaN, "%"+withQuiet
	}
	predicateType := "i1"
	if lanes > 1 {
		predicateType = fmt.Sprintf("<%d x i1>", lanes)
	}
	anyNaN, chosen, selected, rawHardware := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", anyNaN, predicateType, nan[0], nan[1])
	fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", chosen, predicateType, nan[0], integerType, quieted[0], integerType, quieted[1])
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rawHardware, typ, hardware, integerType)
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %%%s, %s %%%s\n", selected, predicateType, anyNaN, integerType, chosen, integerType, rawHardware)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", result, integerType, selected, typ)
	return "%" + result
}

func (c *amd64Ctx) emitRoundedFloatMulDiv(form x86FloatMulDivForm, lanes int, left, right string) string {
	typ, vectorType := amd64FMA3LLVMType(1, form.bits), amd64FMA3LLVMType(lanes, form.bits)
	mode, mxcsr := c.packedNumericRoundingMode(form.rounding), c.loadMXCSR()
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		values := [2]string{left, right}
		if lanes > 1 {
			for index, value := range values {
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, vectorType, value, lane)
				values[index] = "%" + extracted
			}
		}
		for index, floating := range values {
			raw := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", raw, typ, floating, form.bits)
			values[index] = "%" + raw
		}
		raw, value := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i%d @__plan9asm_mul_div_round_f%d(i%d %s, i%d %s, i1 %t, i32 %s, i32 %s)\n", raw, form.bits, form.bits, form.bits, values[0], form.bits, values[1], (form.spec.mode == amd64BinaryFloatingDiv), mode, mxcsr)
		fmt.Fprintf(c.b, "  %%%s = bitcast i%d %%%s to %s\n", value, form.bits, raw, typ)
		if lanes == 1 {
			return "%" + value
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, vectorType, result, typ, value, lane)
		result = "%" + inserted
	}
	return result
}
