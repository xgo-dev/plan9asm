package plan9asm

import "fmt"

func (c *amd64Ctx) x87PortableIR(format string, arguments ...any) string {
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s\n", value, fmt.Sprintf(format, arguments...))
	return "%" + value
}

// x87PortableFromFloat widens the actual IEEE encoding without an intermediate
// floating operation. Masked FLD loads quiet signaling NaNs while retaining
// their sign and remaining payload. Software exception flags are separate.
func (c *amd64Ctx) x87PortableFromFloat(value string, bits int) (x87Value, error) {
	precision, bias, maximum, typ := 53, 1023, 2047, "double"
	if bits == 32 {
		precision, bias, maximum, typ = 24, 127, 255, "float"
	} else if bits != 64 {
		return "", fmt.Errorf("unsupported x87 floating input width %d", bits)
	}
	fractionBits := precision - 1
	raw := c.x87PortableIR("bitcast %s %s to i%d", typ, value, bits)
	if bits == 32 {
		raw = c.x87PortableIR("zext i32 %s to i64", raw)
	}
	sign := c.x87PortableIR("lshr i64 %s, %d", raw, bits-1)
	sign = c.x87PortableIR("shl i64 %s, 15", sign)
	exponent := c.x87PortableIR("lshr i64 %s, %d", raw, fractionBits)
	exponent = c.x87PortableIR("and i64 %s, %d", exponent, maximum)
	fraction := c.x87PortableIR("and i64 %s, %d", raw, uint64(1)<<fractionBits-1)
	leading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", fraction)
	safeLeading := c.x87PortableIR("and i64 %s, 63", leading)
	subnormal := c.x87PortableIR("shl i64 %s, %s", fraction, safeLeading)
	subExponent := c.x87PortableIR("sub i64 %d, %s", 16383+64-bias-fractionBits, leading)
	zero := c.x87PortableIR("icmp eq i64 %s, 0", fraction)
	subExponent = c.x87PortableIR("select i1 %s, i64 0, i64 %s", zero, subExponent)
	significand := c.x87PortableIR("or i64 %s, %d", fraction, uint64(1)<<fractionBits)
	significand = c.x87PortableIR("shl i64 %s, %d", significand, 64-precision)
	normalExponent := c.x87PortableIR("add i64 %s, %d", exponent, 16383-bias)
	special := c.x87PortableIR("icmp eq i64 %s, %d", exponent, maximum)
	nonzeroFraction := c.x87PortableIR("xor i1 %s, true", zero)
	isNaN := c.x87PortableIR("and i1 %s, %s", special, nonzeroFraction)
	quiet := c.x87PortableIR("or i64 %s, 4611686018427387904", significand)
	significand = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", isNaN, quiet, significand)
	normalExponent = c.x87PortableIR("select i1 %s, i64 32767, i64 %s", special, normalExponent)
	isSubnormal := c.x87PortableIR("icmp eq i64 %s, 0", exponent)
	significand = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", isSubnormal, subnormal, significand)
	exponent = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", isSubnormal, subExponent, normalExponent)
	exponent = c.x87PortableIR("or i64 %s, %s", exponent, sign)
	exponent = c.x87PortableIR("trunc i64 %s to i16", exponent)
	return c.packX87(significand, exponent), nil
}

// x87PortableRoundedShift rounds a nonnegative significand divided by 2^shift.
// Every LLVM shift is bounded, including underflow farther than 64 bits. The
// explicit sign and loaded CW select nearest-even, down, up or toward zero.
func (c *amd64Ctx) x87PortableRoundedShift(value, shift, negative, cw string) string {
	wide := c.x87PortableIR("icmp uge i32 %s, 64", shift)
	bounded := c.x87PortableIR("select i1 %s, i32 63, i32 %s", wide, shift)
	bounded = c.x87PortableIR("zext i32 %s to i64", bounded)
	quotient := c.x87PortableIR("lshr i64 %s, %s", value, bounded)
	quotient = c.x87PortableIR("select i1 %s, i64 0, i64 %s", wide, quotient)
	mask := c.x87PortableIR("shl i64 1, %s", bounded)
	mask = c.x87PortableIR("sub i64 %s, 1", mask)
	mask = c.x87PortableIR("select i1 %s, i64 -1, i64 %s", wide, mask)
	remainder := c.x87PortableIR("and i64 %s, %s", value, mask)
	discarded := c.x87PortableIR("icmp ne i64 %s, 0", remainder)
	halfShift := c.x87PortableIR("sub i32 %s, 1", shift)
	halfShift = c.x87PortableIR("and i32 %s, 63", halfShift)
	halfShift = c.x87PortableIR("zext i32 %s to i64", halfShift)
	half := c.x87PortableIR("shl i64 1, %s", halfShift)
	above := c.x87PortableIR("icmp ugt i64 %s, %s", remainder, half)
	tie := c.x87PortableIR("icmp eq i64 %s, %s", remainder, half)
	odd := c.x87PortableIR("and i64 %s, 1", quotient)
	oddBit := c.x87PortableIR("icmp ne i64 %s, 0", odd)
	tie = c.x87PortableIR("and i1 %s, %s", tie, oddBit)
	nearest := c.x87PortableIR("or i1 %s, %s", above, tie)
	withinHalf := c.x87PortableIR("icmp ule i32 %s, 64", shift)
	nearest = c.x87PortableIR("and i1 %s, %s", nearest, withinHalf)
	rounding := c.x87PortableIR("lshr i16 %s, 10", cw)
	rounding = c.x87PortableIR("and i16 %s, 3", rounding)
	isNearest := c.x87PortableIR("icmp eq i16 %s, 0", rounding)
	isDown := c.x87PortableIR("icmp eq i16 %s, 1", rounding)
	isUp := c.x87PortableIR("icmp eq i16 %s, 2", rounding)
	positive := c.x87PortableIR("xor i1 %s, true", negative)
	down := c.x87PortableIR("and i1 %s, %s", isDown, negative)
	up := c.x87PortableIR("and i1 %s, %s", isUp, positive)
	directed := c.x87PortableIR("or i1 %s, %s", down, up)
	increment := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", isNearest, nearest, directed)
	increment = c.x87PortableIR("and i1 %s, %s", increment, discarded)
	increment = c.x87PortableIR("zext i1 %s to i64", increment)
	return c.x87PortableIR("add i64 %s, %s", quotient, increment)
}

// x87PortableToFloat narrows using integer guard/round/sticky information. Its
// result is the actual LLVM float/double SSA value. No floating intermediary or
// host rounding mode is used; CW observation and exception authority stay with
// the existing caller rather than this mathematical provider.
func (c *amd64Ctx) x87PortableToFloat(value x87Value, bits int, cw string) (string, error) {
	precision, bias, maximum, typ := 53, 1023, 2047, "double"
	if bits == 32 {
		precision, bias, maximum, typ = 24, 127, 255, "float"
	} else if bits != 64 {
		return "", fmt.Errorf("unsupported x87 floating result width %d", bits)
	}
	significand, signExponent := c.partsX87(value)
	exponent := c.x87PortableIR("and i16 %s, 32767", signExponent)
	exponent = c.x87PortableIR("zext i16 %s to i32", exponent)
	negative := c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
	zeroExponent := c.x87PortableIR("icmp eq i32 %s, 0", exponent)
	effectiveExponent := c.x87PortableIR("select i1 %s, i32 1, i32 %s", zeroExponent, exponent)
	leading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", significand)
	safeLeading := c.x87PortableIR("and i64 %s, 63", leading)
	normalized := c.x87PortableIR("shl i64 %s, %s", significand, safeLeading)
	leading32 := c.x87PortableIR("trunc i64 %s to i32", leading)
	effectiveExponent = c.x87PortableIR("sub i32 %s, %s", effectiveExponent, leading32)
	outputExponent := c.x87PortableIR("sub i32 %s, %d", effectiveExponent, 16383-bias)
	subnormal := c.x87PortableIR("icmp sle i32 %s, 0", outputExponent)
	extra := c.x87PortableIR("sub i32 1, %s", outputExponent)
	extra = c.x87PortableIR("select i1 %s, i32 %s, i32 0", subnormal, extra)
	shift := c.x87PortableIR("add i32 %s, %d", extra, 64-precision)
	rounded := c.x87PortableRoundedShift(normalized, shift, negative, cw)
	carry := c.x87PortableIR("icmp uge i64 %s, %d", rounded, uint64(1)<<precision)
	shrunk := c.x87PortableIR("lshr i64 %s, 1", rounded)
	significandResult := c.x87PortableIR("select i1 %s, i64 %s, i64 %s", carry, shrunk, rounded)
	carry32 := c.x87PortableIR("zext i1 %s to i32", carry)
	normalExponent := c.x87PortableIR("add i32 %s, %s", outputExponent, carry32)
	subnormalCarry := c.x87PortableIR("icmp uge i64 %s, %d", rounded, uint64(1)<<(precision-1))
	subnormalExponent := c.x87PortableIR("zext i1 %s to i32", subnormalCarry)
	finalExponent := c.x87PortableIR("select i1 %s, i32 %s, i32 %s", subnormal, subnormalExponent, normalExponent)
	overflow := c.x87PortableIR("icmp sge i32 %s, %d", finalExponent, maximum)
	fraction := c.x87PortableIR("and i64 %s, %d", significandResult, uint64(1)<<(precision-1)-1)
	packedExponent := c.x87PortableIR("zext i32 %s to i64", finalExponent)
	packedExponent = c.x87PortableIR("shl i64 %s, %d", packedExponent, precision-1)
	packed := c.x87PortableIR("or i64 %s, %s", packedExponent, fraction)
	rounding := c.x87PortableIR("lshr i16 %s, 10", cw)
	rounding = c.x87PortableIR("and i16 %s, 3", rounding)
	nearest := c.x87PortableIR("icmp eq i16 %s, 0", rounding)
	down := c.x87PortableIR("icmp eq i16 %s, 1", rounding)
	up := c.x87PortableIR("icmp eq i16 %s, 2", rounding)
	positive := c.x87PortableIR("xor i1 %s, true", negative)
	down = c.x87PortableIR("and i1 %s, %s", down, negative)
	up = c.x87PortableIR("and i1 %s, %s", up, positive)
	infinite := c.x87PortableIR("or i1 %s, %s", down, up)
	infinite = c.x87PortableIR("or i1 %s, %s", infinite, nearest)
	infinityBits := uint64(maximum) << (precision - 1)
	overflowBits := c.x87PortableIR("select i1 %s, i64 %d, i64 %d", infinite, infinityBits, infinityBits-1)
	packed = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", overflow, overflowBits, packed)
	sign := c.x87PortableIR("select i1 %s, i64 %d, i64 0", negative, uint64(1)<<(bits-1))
	packed = c.x87PortableIR("or i64 %s, %s", packed, sign)
	special := c.x87PortableIR("icmp eq i32 %s, 32767", exponent)
	payload := c.x87PortableIR("and i64 %s, 9223372036854775807", significand)
	isNaN := c.x87PortableIR("icmp ne i64 %s, 0", payload)
	payload = c.x87PortableIR("lshr i64 %s, %d", payload, 64-precision)
	payload = c.x87PortableIR("or i64 %s, %d", payload, uint64(1)<<(precision-2))
	payload = c.x87PortableIR("select i1 %s, i64 %s, i64 0", isNaN, payload)
	specialBits := c.x87PortableIR("or i64 %s, %d", payload, infinityBits)
	specialBits = c.x87PortableIR("or i64 %s, %s", specialBits, sign)
	packed = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", special, specialBits, packed)
	integerBitMissing := c.x87PortableIR("icmp sge i64 %s, 0", significand)
	nonzeroExponent := c.x87PortableIR("xor i1 %s, true", zeroExponent)
	unsupported := c.x87PortableIR("and i1 %s, %s", integerBitMissing, nonzeroExponent)
	indefinite := uint64(1)<<(bits-1) | infinityBits | uint64(1)<<(precision-2)
	packed = c.x87PortableIR("select i1 %s, i64 %d, i64 %s", unsupported, indefinite, packed)
	if bits == 32 {
		packed = c.x87PortableIR("trunc i64 %s to i32", packed)
	}
	return c.x87PortableIR("bitcast i%d %s to %s", bits, packed, typ), nil
}

func (c *amd64Ctx) x87PortableFromSigned(value string, bits int) (x87Value, error) {
	if bits != 16 && bits != 32 && bits != 64 {
		return "", fmt.Errorf("unsupported x87 signed input width %d", bits)
	}
	if bits != 64 {
		value = c.x87PortableIR("sext i%d %s to i64", bits, value)
	}
	negative := c.x87PortableIR("icmp slt i64 %s, 0", value)
	negated := c.x87PortableIR("sub i64 0, %s", value)
	magnitude := c.x87PortableIR("select i1 %s, i64 %s, i64 %s", negative, negated, value)
	leading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", magnitude)
	safeLeading := c.x87PortableIR("and i64 %s, 63", leading)
	significand := c.x87PortableIR("shl i64 %s, %s", magnitude, safeLeading)
	exponent := c.x87PortableIR("sub i64 16446, %s", leading)
	zero := c.x87PortableIR("icmp eq i64 %s, 0", magnitude)
	exponent = c.x87PortableIR("select i1 %s, i64 0, i64 %s", zero, exponent)
	sign := c.x87PortableIR("select i1 %s, i64 32768, i64 0", negative)
	exponent = c.x87PortableIR("or i64 %s, %s", exponent, sign)
	exponent = c.x87PortableIR("trunc i64 %s to i16", exponent)
	return c.packX87(significand, exponent), nil
}

func (c *amd64Ctx) x87PortableToSigned(value x87Value, bits int, cw string) (string, error) {
	if bits != 16 && bits != 32 && bits != 64 {
		return "", fmt.Errorf("unsupported x87 signed result width %d", bits)
	}
	significand, signExponent := c.partsX87(value)
	negative := c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
	exponent := c.x87PortableIR("and i16 %s, 32767", signExponent)
	exponent = c.x87PortableIR("zext i16 %s to i32", exponent)
	zeroExponent := c.x87PortableIR("icmp eq i32 %s, 0", exponent)
	effectiveExponent := c.x87PortableIR("select i1 %s, i32 1, i32 %s", zeroExponent, exponent)
	shift := c.x87PortableIR("sub i32 16446, %s", effectiveExponent)
	tooLarge := c.x87PortableIR("icmp slt i32 %s, 0", shift)
	shift = c.x87PortableIR("select i1 %s, i32 0, i32 %s", tooLarge, shift)
	rounded := c.x87PortableRoundedShift(significand, shift, negative, cw)
	bound := uint64(1) << (bits - 1)
	positiveRange := c.x87PortableIR("icmp ult i64 %s, %d", rounded, bound)
	negativeRange := c.x87PortableIR("icmp ule i64 %s, %d", rounded, bound)
	valid := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", negative, negativeRange, positiveRange)
	exponentRange := c.x87PortableIR("icmp ule i32 %s, %d", effectiveExponent, 16383+bits-1)
	valid = c.x87PortableIR("and i1 %s, %s", valid, exponentRange)
	integerBit := c.x87PortableIR("icmp slt i64 %s, 0", significand)
	supported := c.x87PortableIR("or i1 %s, %s", zeroExponent, integerBit)
	valid = c.x87PortableIR("and i1 %s, %s", valid, supported)
	negated := c.x87PortableIR("sub i64 0, %s", rounded)
	result := c.x87PortableIR("select i1 %s, i64 %s, i64 %s", negative, negated, rounded)
	result = c.x87PortableIR("select i1 %s, i64 %s, i64 %d", valid, result, bound)
	if bits != 64 {
		result = c.x87PortableIR("trunc i64 %s to i%d", result, bits)
	}
	return result, nil
}

func (c *amd64Ctx) x87PortableConstant(op Op, cw string) (x87Value, error) {
	var significand uint64
	var exponent uint16
	var nearestUp, exact bool
	switch op {
	case "FLDZ":
		exact = true
	case "FLD1":
		significand, exponent, exact = 0x8000000000000000, 0x3fff, true
	case "FLDPI":
		significand, exponent, nearestUp = 0xc90fdaa22168c234, 0x4000, true
	case "FLDL2E":
		significand, exponent, nearestUp = 0xb8aa3b295c17f0bb, 0x3fff, true
	case "FLDL2T":
		significand, exponent = 0xd49a784bcd1b8afe, 0x4000
	case "FLDLG2":
		significand, exponent, nearestUp = 0x9a209a84fbcff798, 0x3ffd, true
	case "FLDLN2":
		significand, exponent, nearestUp = 0xb17217f7d1cf79ab, 0x3ffe, true
	default:
		return "", fmt.Errorf("unsupported x87 constant %s", op)
	}
	low := fmt.Sprint(significand)
	if !exact {
		rounding := c.x87PortableIR("lshr i16 %s, 10", cw)
		rounding = c.x87PortableIR("and i16 %s, 3", rounding)
		increment := c.x87PortableIR("icmp eq i16 %s, 2", rounding)
		if nearestUp {
			nearest := c.x87PortableIR("icmp eq i16 %s, 0", rounding)
			increment = c.x87PortableIR("or i1 %s, %s", increment, nearest)
		}
		increment = c.x87PortableIR("zext i1 %s to i64", increment)
		low = c.x87PortableIR("add i64 %d, %s", significand, increment)
	}
	return c.packX87(low, fmt.Sprint(exponent)), nil
}

func (c *amd64Ctx) x87PortableCompare(left, right x87Value) (equal, less, unordered string) {
	leftSignificand, leftSignExponent := c.partsX87(left)
	rightSignificand, rightSignExponent := c.partsX87(right)
	exponents := [2]string{}
	negative := [2]string{}
	invalid := [2]string{}
	zeros := [2]string{}
	for index, parts := range [][2]string{{leftSignificand, leftSignExponent}, {rightSignificand, rightSignExponent}} {
		significand, signExponent := parts[0], parts[1]
		exponent := c.x87PortableIR("and i16 %s, 32767", signExponent)
		zeroExponent := c.x87PortableIR("icmp eq i16 %s, 0", exponent)
		exponents[index] = c.x87PortableIR("select i1 %s, i16 1, i16 %s", zeroExponent, exponent)
		negative[index] = c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
		missingInteger := c.x87PortableIR("icmp sge i64 %s, 0", significand)
		nonzeroExponent := c.x87PortableIR("xor i1 %s, true", zeroExponent)
		unsupported := c.x87PortableIR("and i1 %s, %s", missingInteger, nonzeroExponent)
		special := c.x87PortableIR("icmp eq i16 %s, 32767", exponent)
		payload := c.x87PortableIR("icmp ne i64 %s, 9223372036854775808", significand)
		nan := c.x87PortableIR("and i1 %s, %s", special, payload)
		invalid[index] = c.x87PortableIR("or i1 %s, %s", unsupported, nan)
		zero := c.x87PortableIR("icmp eq i64 %s, 0", significand)
		zeros[index] = c.x87PortableIR("and i1 %s, %s", zero, zeroExponent)
	}
	unordered = c.x87PortableIR("or i1 %s, %s", invalid[0], invalid[1])
	ordered := c.x87PortableIR("xor i1 %s, true", unordered)
	equalExponent := c.x87PortableIR("icmp eq i16 %s, %s", exponents[0], exponents[1])
	equalSignificand := c.x87PortableIR("icmp eq i64 %s, %s", leftSignificand, rightSignificand)
	equalMagnitude := c.x87PortableIR("and i1 %s, %s", equalExponent, equalSignificand)
	differentSign := c.x87PortableIR("xor i1 %s, %s", negative[0], negative[1])
	sameSign := c.x87PortableIR("xor i1 %s, true", differentSign)
	equal = c.x87PortableIR("and i1 %s, %s", equalMagnitude, sameSign)
	bothZero := c.x87PortableIR("and i1 %s, %s", zeros[0], zeros[1])
	equal = c.x87PortableIR("or i1 %s, %s", equal, bothZero)
	equal = c.x87PortableIR("and i1 %s, %s", equal, ordered)
	leftExponentLess := c.x87PortableIR("icmp ult i16 %s, %s", exponents[0], exponents[1])
	rightExponentLess := c.x87PortableIR("icmp ugt i16 %s, %s", exponents[0], exponents[1])
	leftSignificandLess := c.x87PortableIR("icmp ult i64 %s, %s", leftSignificand, rightSignificand)
	rightSignificandLess := c.x87PortableIR("icmp ugt i64 %s, %s", leftSignificand, rightSignificand)
	leftMagnitudeLess := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", equalExponent, leftSignificandLess, leftExponentLess)
	rightMagnitudeLess := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", equalExponent, rightSignificandLess, rightExponentLess)
	less = c.x87PortableIR("select i1 %s, i1 %s, i1 %s", negative[0], rightMagnitudeLess, leftMagnitudeLess)
	less = c.x87PortableIR("select i1 %s, i1 %s, i1 %s", differentSign, negative[0], less)
	notBothZero := c.x87PortableIR("xor i1 %s, true", bothZero)
	less = c.x87PortableIR("and i1 %s, %s", less, notBothZero)
	less = c.x87PortableIR("and i1 %s, %s", less, ordered)
	return
}

func (c *amd64Ctx) x87PortableClassify(value x87Value) string {
	significand, signExponent := c.partsX87(value)
	exponent := c.x87PortableIR("and i16 %s, 32767", signExponent)
	zeroExponent := c.x87PortableIR("icmp eq i16 %s, 0", exponent)
	integerBit := c.x87PortableIR("icmp slt i64 %s, 0", significand)
	zero := c.x87PortableIR("icmp eq i64 %s, 0", significand)
	denormal := c.x87PortableIR("select i1 %s, i16 16384, i16 17408", zero)
	finite := c.x87PortableIR("select i1 %s, i16 1024, i16 0", integerBit)
	// A pseudo-denormal has the same value as exponent-one normal storage.
	finite = c.x87PortableIR("select i1 %s, i16 %s, i16 %s", zeroExponent, denormal, finite)
	finite = c.x87PortableIR("select i1 %s, i16 1024, i16 %s", integerBit, finite)
	special := c.x87PortableIR("icmp eq i16 %s, 32767", exponent)
	infinity := c.x87PortableIR("icmp eq i64 %s, 9223372036854775808", significand)
	nanOrInfinity := c.x87PortableIR("select i1 %s, i16 1280, i16 256", infinity)
	nanOrInfinity = c.x87PortableIR("select i1 %s, i16 %s, i16 0", integerBit, nanOrInfinity)
	classification := c.x87PortableIR("select i1 %s, i16 %s, i16 %s", special, nanOrInfinity, finite)
	negative := c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
	sign := c.x87PortableIR("select i1 %s, i16 512, i16 0", negative)
	return c.x87PortableIR("or i16 %s, %s", classification, sign)
}
