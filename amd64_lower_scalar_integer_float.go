package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ScalarIntegerFloatSpec struct {
	sourceBits int
	resultBits int
	unsigned   bool
	rounding   bool
}

// This is the complete Go 1.27 scalar integer-to-floating-point family from
// _yvcvtsi2sdl and _yvcvtusi2sdl. It is also the source of truth used by the
// supported-opcode extractor.
var amd64ScalarIntegerFloatOps = map[string]amd64ScalarIntegerFloatSpec{
	"VCVTSI2SDL":  {sourceBits: 32, resultBits: 64},
	"VCVTSI2SDQ":  {sourceBits: 64, resultBits: 64, rounding: true},
	"VCVTSI2SSL":  {sourceBits: 32, resultBits: 32, rounding: true},
	"VCVTSI2SSQ":  {sourceBits: 64, resultBits: 32, rounding: true},
	"VCVTUSI2SDL": {sourceBits: 32, resultBits: 64, unsigned: true},
	"VCVTUSI2SDQ": {sourceBits: 64, resultBits: 64, unsigned: true, rounding: true},
	"VCVTUSI2SSL": {sourceBits: 32, resultBits: 32, unsigned: true, rounding: true},
	"VCVTUSI2SSQ": {sourceBits: 64, resultBits: 32, unsigned: true, rounding: true},
}

func (c *amd64Ctx) lowerScalarIntegerToFloat(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64ScalarIntegerFloatOps[baseOp]
	if !recognized {
		return false, false, nil
	}
	rounding := ""
	switch suffix {
	case "":
	case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
		if !spec.rounding {
			return true, false, fmt.Errorf("%s %s does not enable explicit rounding: %q", c.goarch, baseOp, ins.Raw)
		}
		rounding = suffix
	default:
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's scalar integer-to-float tables: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects integer source, X passthrough, X destination: %q", c.goarch, baseOp, ins.Raw)
	}
	source, passthrough, destination := ins.Args[0], ins.Args[1], ins.Args[2]
	if source.Kind == OpReg {
		if !c.isGoYrlRegister(source) {
			return true, false, fmt.Errorf("%s %s integer source is outside Go 1.27's GP-register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s integer source must be a GP register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if rounding != "" && source.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s explicit rounding requires a GP-register source: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(passthrough, 16) || !c.isGoEVEXVectorRegister(destination, 16) {
		return true, false, fmt.Errorf("%s %s passthrough and destination must be Go 1.27 X registers: %q", c.goarch, baseOp, ins.Raw)
	}

	integerType := amd64IntegerTypeForBits(spec.sourceBits)
	integer, err := c.evalIntSized(source, integerType)
	if err != nil {
		return true, false, err
	}
	floatType := LLVMType("float")
	if spec.resultBits == 64 {
		floatType = LLVMType("double")
	}
	conversion := "sitofp"
	if spec.unsigned {
		conversion = "uitofp"
	}
	var low string
	if rounding == "" {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", converted, conversion, integerType, integer, floatType)
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to i%d\n", bits, floatType, converted, spec.resultBits)
		low = "%" + bits
	} else {
		low = c.emitRoundedScalarIntegerToFloatBits(integer, spec, rounding)
	}
	passthroughBytes, err := c.loadX(passthrough.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.resultBits, spec.resultBits, passthroughBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.resultBits, low, base, "", false)
}

// emitRoundedScalarIntegerToFloatBits converts through an explicit integer
// significand so embedded rounding remains correct even when LLVM 22 lowers a
// constrained conversion to an instruction controlled by the ambient MXCSR.
func (c *amd64Ctx) emitRoundedScalarIntegerToFloatBits(integer string, spec amd64ScalarIntegerFloatSpec, rounding string) string {
	integerType := amd64IntegerTypeForBits(spec.sourceBits)
	precision := 24
	bias := 127
	if spec.resultBits == 64 {
		precision = 53
		bias = 1023
	}

	negative := "false"
	magnitude := integer
	if !spec.unsigned {
		isNegative := c.newTmp()
		negated := c.newTmp()
		absolute := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", isNegative, integerType, integer)
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", negated, integerType, integer)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %s\n", absolute, isNegative, integerType, negated, integerType, integer)
		negative = "%" + isNegative
		magnitude = "%" + absolute
	}

	isZero := c.newTmp()
	safeMagnitude := c.newTmp()
	leadingZeros := c.newTmp()
	msb := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", isZero, integerType, magnitude)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 1, %s %s\n", safeMagnitude, isZero, integerType, integerType, magnitude)
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.ctlz.i%d(%s %%%s, i1 false)\n", leadingZeros, integerType, spec.sourceBits, integerType, safeMagnitude)
	fmt.Fprintf(c.b, "  %%%s = sub %s %d, %%%s\n", msb, integerType, spec.sourceBits-1, leadingZeros)

	needsRightShift := c.newTmp()
	rawRightShift := c.newTmp()
	rightShift := c.newTmp()
	rawLeftShift := c.newTmp()
	leftShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp uge %s %%%s, %d\n", needsRightShift, integerType, msb, precision-1)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, %d\n", rawRightShift, integerType, msb, precision-1)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", rightShift, needsRightShift, integerType, rawRightShift, integerType)
	fmt.Fprintf(c.b, "  %%%s = sub %s %d, %%%s\n", rawLeftShift, integerType, precision-1, msb)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", leftShift, needsRightShift, integerType, integerType, rawLeftShift)

	shiftedRight := c.newTmp()
	shiftedLeft := c.newTmp()
	significand := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", shiftedRight, integerType, magnitude, rightShift)
	fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", shiftedLeft, integerType, magnitude, leftShift)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", significand, needsRightShift, integerType, shiftedRight, integerType, shiftedLeft)

	oneAtShift := c.newTmp()
	remainderMask := c.newTmp()
	remainder := c.newTmp()
	inexact := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", oneAtShift, integerType, rightShift)
	fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, 1\n", remainderMask, integerType, oneAtShift)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", remainder, integerType, magnitude, remainderMask)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", inexact, integerType, remainder)

	increment := "false"
	switch rounding {
	case "RN_SAE":
		hasShift := c.newTmp()
		rawHalfShift := c.newTmp()
		halfShift := c.newTmp()
		half := c.newTmp()
		aboveHalf := c.newTmp()
		equalHalf := c.newTmp()
		lowBit := c.newTmp()
		odd := c.newTmp()
		tieAndOdd := c.newTmp()
		roundNearest := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", hasShift, integerType, rightShift)
		fmt.Fprintf(c.b, "  %%%s = sub %s %%%s, 1\n", rawHalfShift, integerType, rightShift)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s 0\n", halfShift, hasShift, integerType, rawHalfShift, integerType)
		fmt.Fprintf(c.b, "  %%%s = shl %s 1, %%%s\n", half, integerType, halfShift)
		fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %%%s\n", aboveHalf, integerType, remainder, half)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %%%s\n", equalHalf, integerType, remainder, half)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", lowBit, integerType, significand)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", odd, integerType, lowBit)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tieAndOdd, equalHalf, odd)
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", roundNearest, aboveHalf, tieAndOdd)
		increment = "%" + roundNearest
	case "RD_SAE":
		if !spec.unsigned {
			roundDown := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i1 %s, %%%s\n", roundDown, negative, inexact)
			increment = "%" + roundDown
		}
	case "RU_SAE":
		if spec.unsigned {
			increment = "%" + inexact
		} else {
			positive := c.newTmp()
			roundUp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", positive, negative)
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", roundUp, positive, inexact)
			increment = "%" + roundUp
		}
	}

	incrementInteger := c.newTmp()
	roundedSignificand := c.newTmp()
	overflow := c.newTmp()
	normalizedOverflow := c.newTmp()
	normalized := c.newTmp()
	exponentIncrement := c.newTmp()
	exponent := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to %s\n", incrementInteger, increment, integerType)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", roundedSignificand, integerType, significand, incrementInteger)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %d\n", overflow, integerType, roundedSignificand, uint64(1)<<precision)
	fmt.Fprintf(c.b, "  %%%s = lshr %s %%%s, 1\n", normalizedOverflow, integerType, roundedSignificand)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %%%s\n", normalized, overflow, integerType, normalizedOverflow, integerType, roundedSignificand)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to %s\n", exponentIncrement, overflow, integerType)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %%%s\n", exponent, integerType, msb, exponentIncrement)

	mantissa := c.newTmp()
	biasedExponent := c.newTmp()
	encodedExponent := c.newTmp()
	encodedMagnitude := c.newTmp()
	signWord := c.newTmp()
	encoded := c.newTmp()
	nonzeroBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", mantissa, integerType, normalized, (uint64(1)<<(precision-1))-1)
	fmt.Fprintf(c.b, "  %%%s = add %s %%%s, %d\n", biasedExponent, integerType, exponent, bias)
	fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %d\n", encodedExponent, integerType, biasedExponent, precision-1)
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", encodedMagnitude, integerType, encodedExponent, mantissa)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %d, %s 0\n", signWord, negative, integerType, uint64(1)<<(spec.resultBits-1), integerType)
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", encoded, integerType, encodedMagnitude, signWord)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s 0, %s %%%s\n", nonzeroBits, isZero, integerType, integerType, encoded)
	if spec.resultBits == spec.sourceBits {
		return "%" + nonzeroBits
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to i%d\n", result, integerType, nonzeroBits, spec.resultBits)
	return "%" + result
}
