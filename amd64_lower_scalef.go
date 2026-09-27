package plan9asm

import "fmt"

type amd64ScaleFControls struct {
	daz      string
	ftz      string
	rounding string
}

func (c *amd64Ctx) scaleFControls(rounding string) amd64ScaleFControls {
	mxcsr := c.loadMXCSR()
	dazBits, daz := c.newTmp(), c.newTmp()
	ftzBits, ftz := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 64\n", dazBits, mxcsr)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", daz, dazBits)
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 32768\n", ftzBits, mxcsr)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", ftz, ftzBits)
	mode := ""
	switch rounding {
	case "RN_SAE":
		mode = "0"
	case "RD_SAE":
		mode = "1"
	case "RU_SAE":
		mode = "2"
	case "RZ_SAE":
		mode = "3"
	default:
		shifted, extracted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, 13\n", shifted, mxcsr)
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 3\n", extracted, shifted)
		mode = "%" + extracted
	}
	return amd64ScaleFControls{daz: "%" + daz, ftz: "%" + ftz, rounding: mode}
}

func (c *amd64Ctx) lowerPackedScaleF(spec amd64BinaryFloatingSpec, properties amd64BinaryFloatingSuffix, source2, source1, destination Operand, byteWidth int, mask string) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	scale, err := c.loadPackedCompareLanes(source2, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	value, err := c.loadPackedCompareLanes(source1, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitScaleFBits(lanes, spec.laneBits, value, scale, c.scaleFControls(properties.rounding))
	if mask != "" {
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarScaleF(spec amd64BinaryFloatingSpec, properties amd64BinaryFloatingSuffix, source2, source1, destination Operand, mask string) (bool, bool, error) {
	scaleBits, err := c.loadFloatingScalarBits(source2, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	valueBits, err := c.loadFloatingScalarBits(source1, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	scale, value := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", scale, spec.laneBits, spec.laneBits, scaleBits)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", value, spec.laneBits, spec.laneBits, valueBits)
	result := c.emitScaleFBits(1, spec.laneBits, "%"+value, "%"+scale, c.scaleFControls(properties.rounding))
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	passthroughBytes, err := c.loadX(source1.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, passthroughBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+low, base, mask, properties.zeroing)
}

func (c *amd64Ctx) emitScaleFBits(lanes, laneBits int, source1, source2 string, controls amd64ScaleFControls) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	mantissaBits, bias, exponentMax, scaleClamp := 23, 127, 255, 512
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	signBit := uint64(0x80000000)
	indefinite := uint64(0xffc00000)
	if laneBits == 64 {
		mantissaBits, bias, exponentMax, scaleClamp = 52, 1023, 2047, 4096
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
		signBit = uint64(0x8000000000000000)
		indefinite = uint64(0xfff8000000000000)
	}
	implicitBit := uint64(1) << mantissaBits
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		x, y := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", x, vectorType, source1, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", y, vectorType, source2, lane)
		laneResult := c.emitScaleFLane(laneBits, mantissaBits, bias, exponentMax, scaleClamp,
			exponentMask, mantissaMask, quietBit, signBit, indefinite, implicitBit,
			"%"+x, "%"+y, controls)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, result, laneBits, laneResult, lane)
		result = "%" + inserted
	}
	return result
}

type amd64ScaleFClass struct {
	bits, sign, fraction, exponent     string
	zero, nan, snan, infinity          string
	positiveInfinity, negativeInfinity string
}

func (c *amd64Ctx) classifyScaleFValue(laneBits, mantissaBits, exponentMax int, exponentMask, mantissaMask, quietBit, signBit uint64, bits, daz string) amd64ScaleFClass {
	sign, fraction, exponentField := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %s, %d\n", sign, laneBits, bits, signBit)
	fmt.Fprintf(c.b, "  %%%s = and i%d %s, %d\n", fraction, laneBits, bits, mantissaMask)
	fmt.Fprintf(c.b, "  %%%s = and i%d %s, %d\n", exponentField, laneBits, bits, exponentMask)
	exponentZero, fractionNonzero, denormal := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", exponentZero, laneBits, exponentField)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", fractionNonzero, laneBits, fraction)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", denormal, exponentZero, fractionNonzero)
	flush := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %s\n", flush, denormal, daz)
	effective := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %s\n", effective, flush, laneBits, sign, laneBits, bits)

	effectiveFraction, shiftedExponent, effectiveExponent := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", effectiveFraction, laneBits, effective, mantissaMask)
	fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %d\n", shiftedExponent, laneBits, effective, mantissaBits)
	if laneBits == 32 {
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, %d\n", effectiveExponent, shiftedExponent, exponentMax)
	} else {
		exponentWide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %d\n", exponentWide, shiftedExponent, exponentMax)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", effectiveExponent, exponentWide)
	}
	abs, isZero, isExponentMax, isFractionNonzero := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", abs, laneBits, effective, signBit-1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", isZero, laneBits, abs)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, %d\n", isExponentMax, effectiveExponent, exponentMax)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", isFractionNonzero, laneBits, effectiveFraction)
	isNaN, isInfinity := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isNaN, isExponentMax, isFractionNonzero)
	fractionQuiet, quietClear, isSNaN := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", fractionQuiet, laneBits, effectiveFraction, quietBit)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", quietClear, laneBits, fractionQuiet)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isSNaN, isNaN, quietClear)
	fractionZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", fractionZero, laneBits, effectiveFraction)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isInfinity, isExponentMax, fractionZero)
	isNegative, positiveInfinity, negativeInfinity := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", isNegative, laneBits, sign)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", negativeInfinity, isInfinity, isNegative)
	notNegative := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notNegative, isNegative)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", positiveInfinity, isInfinity, notNegative)
	return amd64ScaleFClass{
		bits: "%" + effective, sign: "%" + sign, fraction: "%" + effectiveFraction, exponent: "%" + effectiveExponent,
		zero: "%" + isZero, nan: "%" + isNaN, snan: "%" + isSNaN, infinity: "%" + isInfinity,
		positiveInfinity: "%" + positiveInfinity, negativeInfinity: "%" + negativeInfinity,
	}
}

func (c *amd64Ctx) emitScaleFLane(laneBits, mantissaBits, bias, exponentMax, scaleClamp int, exponentMask, mantissaMask, quietBit, signBit, indefinite, implicitBit uint64, source1, source2 string, controls amd64ScaleFControls) string {
	x := c.classifyScaleFValue(laneBits, mantissaBits, exponentMax, exponentMask, mantissaMask, quietBit, signBit, source1, controls.daz)
	y := c.classifyScaleFValue(laneBits, mantissaBits, exponentMax, exponentMask, mantissaMask, quietBit, signBit, source2, controls.daz)

	yNegative := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %s, 0\n", yNegative, laneBits, y.sign)
	yExponentNegative, yExponentLarge := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %s, %d\n", yExponentNegative, y.exponent, bias)
	largeExponent := 9
	if laneBits == 64 {
		largeExponent = 12
	}
	fmt.Fprintf(c.b, "  %%%s = icmp sge i32 %s, %d\n", yExponentLarge, y.exponent, bias+largeExponent)
	yUnbiased, yShift := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %d\n", yUnbiased, y.exponent, bias)
	fmt.Fprintf(c.b, "  %%%s = sub i32 %d, %%%s\n", yShift, mantissaBits, yUnbiased)
	yExponentOutOfRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", yExponentOutOfRange, yExponentNegative, yExponentLarge)
	safeYShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %d, i32 %%%s\n", safeYShift, yExponentOutOfRange, mantissaBits, yShift)
	yShiftLane := "%" + safeYShift
	if laneBits == 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, safeYShift)
		yShiftLane = "%" + wide
	}
	ySignificand := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %d\n", ySignificand, laneBits, y.fraction, implicitBit)
	yIntegerWide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %s\n", yIntegerWide, laneBits, ySignificand, yShiftLane)
	yInteger := "%" + yIntegerWide
	if laneBits == 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", narrow, yIntegerWide)
		yInteger = "%" + narrow
	}
	oneShifted, remainderMask, remainder, remainderNonzero := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i%d 1, %s\n", oneShifted, laneBits, yShiftLane)
	fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, 1\n", remainderMask, laneBits, oneShifted)
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %%%s\n", remainder, laneBits, ySignificand, remainderMask)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", remainderNonzero, laneBits, remainder)
	negativeInteger, negativeFloor := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 0, %s\n", negativeInteger, yInteger)
	remainderAdjust := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", remainderAdjust, remainderNonzero)
	fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", negativeFloor, negativeInteger, remainderAdjust)
	signedInteger := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %s\n", signedInteger, yNegative, negativeFloor, yInteger)
	smallScale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -1, i32 0\n", smallScale, yNegative)
	clampedScale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 -%d, i32 %d\n", clampedScale, yNegative, scaleClamp, scaleClamp)
	nonzeroScale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", nonzeroScale, yExponentLarge, clampedScale, signedInteger)
	finiteScale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 %%%s\n", finiteScale, yExponentNegative, smallScale, nonzeroScale)
	scale := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i32 0, i32 %%%s\n", scale, y.zero, finiteScale)

	xExponentZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", xExponentZero, x.exponent)
	xSignificandNormal := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %d\n", xSignificandNormal, laneBits, x.fraction, implicitBit)
	xSignificand := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %s, i%d %%%s\n", xSignificand, xExponentZero, laneBits, x.fraction, laneBits, xSignificandNormal)
	leadingZeros := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.ctlz.i%d(i%d %%%s, i1 false)\n", leadingZeros, laneBits, laneBits, laneBits, xSignificand)
	leadingZeros32 := "%" + leadingZeros
	if laneBits == 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", narrow, leadingZeros)
		leadingZeros32 = "%" + narrow
	}
	normalizeShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %d\n", normalizeShift, leadingZeros32, laneBits-1-mantissaBits)
	normalizeShiftLane := "%" + normalizeShift
	if laneBits == 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, normalizeShift)
		normalizeShiftLane = "%" + wide
	}
	normalizedSignificand := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i%d %%%s, %s\n", normalizedSignificand, laneBits, xSignificand, normalizeShiftLane)
	xBaseExponentNormal, xBaseExponent := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %d\n", xBaseExponentNormal, x.exponent, bias)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %d, i32 %%%s\n", xBaseExponent, xExponentZero, 1-bias, xBaseExponentNormal)
	xNormalizedExponent := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, %%%s\n", xNormalizedExponent, xBaseExponent, normalizeShift)
	targetExponent := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", targetExponent, xNormalizedExponent, scale)

	overflow, normal := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, %d\n", overflow, targetExponent, bias)
	fmt.Fprintf(c.b, "  %%%s = icmp sge i32 %%%s, %d\n", normal, targetExponent, 1-bias)
	normalExponent32 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %d\n", normalExponent32, targetExponent, bias)
	normalExponent := "%" + normalExponent32
	if laneBits == 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, normalExponent32)
		normalExponent = "%" + wide
	}
	normalExponentBits, normalFraction, normalMagnitude, normalBits := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i%d %s, %d\n", normalExponentBits, laneBits, normalExponent, mantissaBits)
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", normalFraction, laneBits, normalizedSignificand, mantissaMask)
	fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %%%s\n", normalMagnitude, laneBits, normalExponentBits, normalFraction)
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %%%s\n", normalBits, laneBits, x.sign, normalMagnitude)

	subnormalShiftRaw, subnormalShiftHigh := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %d, %%%s\n", subnormalShiftRaw, 1-bias, targetExponent)
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i32 %%%s, %d\n", subnormalShiftHigh, subnormalShiftRaw, mantissaBits+2)
	subnormalShiftMax := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %d, i32 %%%s\n", subnormalShiftMax, subnormalShiftHigh, mantissaBits+2, subnormalShiftRaw)
	subnormalShiftLow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt i32 %%%s, 1\n", subnormalShiftLow, subnormalShiftMax)
	subnormalShift := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 1, i32 %%%s\n", subnormalShift, subnormalShiftLow, subnormalShiftMax)
	subnormalShiftLane := "%" + subnormalShift
	if laneBits == 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, subnormalShift)
		subnormalShiftLane = "%" + wide
	}
	quotient, subOneShifted, subRemainderMask, subRemainder := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %s\n", quotient, laneBits, normalizedSignificand, subnormalShiftLane)
	fmt.Fprintf(c.b, "  %%%s = shl i%d 1, %s\n", subOneShifted, laneBits, subnormalShiftLane)
	fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, 1\n", subRemainderMask, laneBits, subOneShifted)
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %%%s\n", subRemainder, laneBits, normalizedSignificand, subRemainderMask)
	subRemainderNonzero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", subRemainderNonzero, laneBits, subRemainder)
	halfShift32 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", halfShift32, subnormalShift)
	halfShift := "%" + halfShift32
	if laneBits == 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, halfShift32)
		halfShift = "%" + wide
	}
	half, aboveHalf, equalHalf, quotientOdd, tieOdd, nearest := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i%d 1, %s\n", half, laneBits, halfShift)
	fmt.Fprintf(c.b, "  %%%s = icmp ugt i%d %%%s, %%%s\n", aboveHalf, laneBits, subRemainder, half)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %%%s\n", equalHalf, laneBits, subRemainder, half)
	quotientLowBit := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, 1\n", quotientLowBit, laneBits, quotient)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", quotientOdd, laneBits, quotientLowBit)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tieOdd, equalHalf, quotientOdd)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", nearest, aboveHalf, tieOdd)
	xNegative := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %s, 0\n", xNegative, laneBits, x.sign)
	increment := c.emitScaledRoundIncrement(controls.rounding, "%"+xNegative, "%"+subRemainderNonzero, "%"+nearest)
	incrementBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i%d\n", incrementBits, increment, laneBits)
	roundedSubnormal, subnormalBits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i%d %%%s, %%%s\n", roundedSubnormal, laneBits, quotient, incrementBits)
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %%%s\n", subnormalBits, laneBits, x.sign, roundedSubnormal)
	isSubnormal := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i%d %%%s, %d\n", isSubnormal, laneBits, roundedSubnormal, implicitBit)
	flushInexact, flushSubnormal := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %s, %%%s\n", flushInexact, controls.ftz, subRemainderNonzero)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", flushSubnormal, flushInexact, isSubnormal)
	underflowBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %s, i%d %%%s\n", underflowBits, flushSubnormal, laneBits, x.sign, laneBits, subnormalBits)

	toInfinity := c.emitScaledRoundIncrement(controls.rounding, "%"+xNegative, "true", "true")
	overflowInfinity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %d, i%d %d\n", overflowInfinity, toInfinity, laneBits, exponentMask, laneBits, exponentMask-1)
	overflowBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %%%s\n", overflowBits, laneBits, x.sign, overflowInfinity)
	finiteNonOverflow, finiteBits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", finiteNonOverflow, normal, laneBits, normalBits, laneBits, underflowBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", finiteBits, overflow, laneBits, overflowBits, laneBits, finiteNonOverflow)

	yInfinityResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %d, i%d %s\n", yInfinityResult, y.positiveInfinity, laneBits, exponentMask, laneBits, x.sign)
	yInfinitySigned := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %%%s\n", yInfinitySigned, laneBits, x.sign, yInfinityResult)
	general := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", general, y.infinity, laneBits, yInfinitySigned, laneBits, finiteBits)
	xZeroInfinity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %d, i%d %s\n", xZeroInfinity, y.positiveInfinity, laneBits, indefinite, laneBits, x.bits)
	xZeroResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %s\n", xZeroResult, y.infinity, laneBits, xZeroInfinity, laneBits, x.bits)
	withZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", withZero, x.zero, laneBits, xZeroResult, laneBits, general)
	xInfinityResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %d, i%d %s\n", xInfinityResult, y.negativeInfinity, laneBits, indefinite, laneBits, x.bits)
	withInfinity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", withInfinity, x.infinity, laneBits, xInfinityResult, laneBits, withZero)
	quietY := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %d\n", quietY, laneBits, y.bits, quietBit)
	withYNaN := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", withYNaN, y.nan, laneBits, quietY, laneBits, withInfinity)
	quietX := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %d\n", quietX, laneBits, x.bits, quietBit)
	xQNaNInfinity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %d, i%d 0\n", xQNaNInfinity, y.positiveInfinity, laneBits, exponentMask, laneBits)
	xQNaNResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", xQNaNResult, y.infinity, laneBits, xQNaNInfinity, laneBits, quietX)
	xQNaN := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %s, true\n", xQNaN, x.nan)
	notSNaN := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", notSNaN, x.snan)
	isQNaN := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isQNaN, xQNaN, notSNaN)
	withXQNaN := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", withXQNaN, isQNaN, laneBits, xQNaNResult, laneBits, withYNaN)
	final := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", final, x.snan, laneBits, quietX, laneBits, withXQNaN)
	return "%" + final
}
