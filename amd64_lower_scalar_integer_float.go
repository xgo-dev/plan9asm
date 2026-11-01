package plan9asm

import "fmt"

type amd64ScalarIntegerFloatSpec struct {
	sourceBits int
	resultBits int
	unsigned   bool
	rounding   bool
}

// Complete unsigned _yvcvtusi2sdl family. Signed legacy/VEX forms retain their
// independent table. Supported-op extraction reads both registries.
var amd64ScalarIntegerFloatOps = map[string]amd64ScalarIntegerFloatSpec{
	"VCVTUSI2SDL": {sourceBits: 32, resultBits: 64, unsigned: true},
	"VCVTUSI2SDQ": {sourceBits: 64, resultBits: 64, unsigned: true, rounding: true},
	"VCVTUSI2SSL": {sourceBits: 32, resultBits: 32, unsigned: true, rounding: true},
	"VCVTUSI2SSQ": {sourceBits: 64, resultBits: 32, unsigned: true, rounding: true},
}

func (c *amd64Ctx) lowerScalarIntegerToFloat(op Op, ins Instr) (bool, bool, error) {
	if ok, term, err := c.lowerSignedIntegerScalarFloat(op, ins); ok {
		return ok, term, err
	}
	return c.lowerUnsignedIntegerScalarFloat(op, ins)
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
