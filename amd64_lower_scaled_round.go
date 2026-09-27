package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ScaledRoundMode uint8

const (
	amd64RoundScale amd64ScaledRoundMode = iota
	amd64Reduce
)

type amd64ScaledRoundSpec struct {
	laneBits int
	scalar   bool
	mode     amd64ScaledRoundMode
}

var amd64ScaledRoundSpecs = map[Op]amd64ScaledRoundSpec{
	"VRNDSCALEPS": {laneBits: 32},
	"VRNDSCALEPD": {laneBits: 64},
	"VRNDSCALESS": {laneBits: 32, scalar: true},
	"VRNDSCALESD": {laneBits: 64, scalar: true},
	"VREDUCEPS":   {laneBits: 32, mode: amd64Reduce},
	"VREDUCEPD":   {laneBits: 64, mode: amd64Reduce},
	"VREDUCESS":   {laneBits: 32, scalar: true, mode: amd64Reduce},
	"VREDUCESD":   {laneBits: 64, scalar: true, mode: amd64Reduce},
}

func (c *amd64Ctx) lowerScaledRound(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64ScaledRoundSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	shape := amd64UnaryImmediateFloatingShape{laneBits: spec.laneBits, scalar: spec.scalar}
	form, err := c.parseUnaryImmediateFloatingForm(baseOp, suffix, shape, ins)
	if err != nil {
		return true, false, err
	}
	mxcsr := c.loadMXCSR()
	dazBits, daz := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 64\n", dazBits, mxcsr)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", daz, dazBits)
	roundingMode := fmt.Sprintf("%d", form.immediate&3)
	if form.immediate&4 != 0 {
		shifted, extracted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, 13\n", shifted, mxcsr)
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 3\n", extracted, shifted)
		roundingMode = "%" + extracted
	}
	if spec.scalar {
		return c.lowerScalarScaledRound(spec, form.properties, form.source, form.passthrough, form.destination, form.mask, "%"+daz, roundingMode, form.immediate)
	}
	return c.lowerPackedScaledRound(spec, form.properties, form.source, form.destination, form.byteWidth, form.mask, "%"+daz, roundingMode, form.immediate)
}

func (c *amd64Ctx) lowerPackedScaledRound(spec amd64ScaledRoundSpec, properties amd64BinaryFloatingSuffix, source, destination Operand, byteWidth int, mask, daz, roundingMode string, immediate uint8) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	input, err := c.loadPackedCompareLanes(source, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	result := c.emitScaledRoundBits(lanes, spec.laneBits, input, daz, roundingMode, immediate>>4, spec.mode)
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

func (c *amd64Ctx) lowerScalarScaledRound(spec amd64ScaledRoundSpec, properties amd64BinaryFloatingSuffix, source, passthrough, destination Operand, mask, daz, roundingMode string, immediate uint8) (bool, bool, error) {
	sourceBits, err := c.loadFloatingScalarBits(source, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", input, spec.laneBits, spec.laneBits, sourceBits)
	result := c.emitScaledRoundBits(1, spec.laneBits, "%"+input, daz, roundingMode, immediate>>4, spec.mode)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	passthroughBytes, err := c.loadX(passthrough.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, passthroughBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+low, base, mask, properties.zeroing)
}

func (c *amd64Ctx) emitScaledRoundBits(lanes, laneBits int, input, daz, roundingMode string, scale uint8, mode amd64ScaledRoundMode) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	mantissaBits, bias := 23, 127
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	signBit := uint64(0x80000000)
	if laneBits == 64 {
		mantissaBits, bias = 52, 1023
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
		signBit = uint64(0x8000000000000000)
	}
	implicitBit := uint64(1) << mantissaBits
	alreadyThreshold := bias + mantissaBits - int(scale)
	regularThreshold := bias - int(scale)
	stepBits := uint64(bias-int(scale)) << mantissaBits
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		bits, exponent, mantissa, sign := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", bits, vectorType, input, lane)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", exponent, laneBits, bits, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", mantissa, laneBits, bits, mantissaMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", sign, laneBits, bits, signBit)
		exponentZero, exponentOnes, mantissaZero := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", exponentZero, laneBits, exponent)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", exponentOnes, laneBits, exponent, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", mantissaZero, laneBits, mantissa)
		mantissaNonzero, negative := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", mantissaNonzero, mantissaZero)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", negative, laneBits, sign)
		isNaN, isInfinity := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isNaN, exponentOnes, mantissaNonzero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isInfinity, exponentOnes, mantissaZero)
		effectiveZeroPart, effectiveZero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", effectiveZeroPart, mantissaZero, daz)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", effectiveZero, exponentZero, effectiveZeroPart)

		exponentField := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %d\n", exponentField, laneBits, exponent, mantissaBits)
		already, regularLower, regularUpper, regular := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp uge i%d %%%s, %d\n", already, laneBits, exponentField, alreadyThreshold)
		fmt.Fprintf(c.b, "  %%%s = icmp uge i%d %%%s, %d\n", regularLower, laneBits, exponentField, regularThreshold)
		fmt.Fprintf(c.b, "  %%%s = icmp ult i%d %%%s, %d\n", regularUpper, laneBits, exponentField, alreadyThreshold)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", regular, regularLower, regularUpper)
		half := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", half, laneBits, exponentField, regularThreshold-1)

		safeExponent, drop := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %d\n", safeExponent, regular, laneBits, exponentField, laneBits, alreadyThreshold-1)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %d, %%%s\n", drop, laneBits, mantissaBits+bias-int(scale), safeExponent)
		significand := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", significand, laneBits, mantissa, implicitBit)
		quotient, oneAtDrop, remainderMask, remainder := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %%%s\n", quotient, laneBits, significand, drop)
		fmt.Fprintf(c.b, "  %%%s = shl i%d 1, %%%s\n", oneAtDrop, laneBits, drop)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, 1\n", remainderMask, laneBits, oneAtDrop)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %%%s\n", remainder, laneBits, significand, remainderMask)
		halfRemainder, aboveHalf, equalHalf := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, 1\n", halfRemainder, laneBits, oneAtDrop)
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i%d %%%s, %%%s\n", aboveHalf, laneBits, remainder, halfRemainder)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %%%s\n", equalHalf, laneBits, remainder, halfRemainder)
		quotientOddValue, quotientOdd, tiedOdd := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, 1\n", quotientOddValue, laneBits, quotient)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", quotientOdd, laneBits, quotientOddValue)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tiedOdd, equalHalf, quotientOdd)
		nearestRegular := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", nearestRegular, aboveHalf, tiedOdd)
		remainderNonzero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", remainderNonzero, laneBits, remainder)
		incrementRegular := c.emitScaledRoundIncrement(roundingMode, "%"+negative, "%"+remainderNonzero, "%"+nearestRegular)
		incrementValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i%d\n", incrementValue, incrementRegular, laneBits)
		roundedQuotient, roundedSignificand := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i%d %%%s, %%%s\n", roundedQuotient, laneBits, quotient, incrementValue)
		fmt.Fprintf(c.b, "  %%%s = shl i%d %%%s, %%%s\n", roundedSignificand, laneBits, roundedQuotient, drop)
		carryValue, carry, carryInteger := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", carryValue, laneBits, roundedSignificand, implicitBit<<1)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", carry, laneBits, carryValue)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i%d\n", carryInteger, carry, laneBits)
		roundedExponentField, roundedExponent := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i%d %%%s, %%%s\n", roundedExponentField, laneBits, exponentField, carryInteger)
		fmt.Fprintf(c.b, "  %%%s = shl i%d %%%s, %d\n", roundedExponent, laneBits, roundedExponentField, mantissaBits)
		roundedFraction, roundedMagnitude, roundedRegular := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", roundedFraction, laneBits, roundedSignificand, mantissaMask)
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %%%s\n", roundedMagnitude, laneBits, roundedExponent, roundedFraction)
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %%%s\n", roundedRegular, laneBits, roundedMagnitude, sign)

		halfAbove := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i%d %%%s, %d\n", halfAbove, laneBits, significand, implicitBit)
		nonzero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", nonzero, effectiveZero)
		incrementHalf := c.emitScaledRoundIncrement(roundingMode, "%"+negative, "%"+nonzero, "%"+halfAbove)
		incrementSmall := c.emitScaledRoundIncrement(roundingMode, "%"+negative, "%"+nonzero, "false")
		incrementNonRegular := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %s, i1 %s\n", incrementNonRegular, half, incrementHalf, incrementSmall)
		signedStep, stepOrZero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", signedStep, laneBits, sign, stepBits)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", stepOrZero, incrementNonRegular, laneBits, signedStep, laneBits, sign)
		roundedNeeded, roundedFinite, zeroAdjusted := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", roundedNeeded, regular, laneBits, roundedRegular, laneBits, stepOrZero)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", roundedFinite, already, laneBits, bits, laneBits, roundedNeeded)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", zeroAdjusted, effectiveZero, laneBits, sign, laneBits, roundedFinite)
		withInfinity := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", withInfinity, isInfinity, laneBits, bits, laneBits, zeroAdjusted)
		quietNaN := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", quietNaN, laneBits, bits, quietBit)
		roundedFinal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", roundedFinal, isNaN, laneBits, quietNaN, laneBits, withInfinity)
		laneResult := "%" + roundedFinal
		if mode == amd64Reduce {
			effectiveSource := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", effectiveSource, effectiveZero, laneBits, sign, laneBits, bits)
			laneResult = c.emitReduceResult(laneBits, "%"+effectiveSource, "%"+zeroAdjusted, "%"+isNaN, "%"+isInfinity, roundingMode, quietBit, signBit)
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, result, laneBits, laneResult, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitScaledRoundIncrement(roundingMode, negative, nonzero, nearest string) string {
	isNearest, isDown, isUp := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", isNearest, roundingMode)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 1\n", isDown, roundingMode)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 2\n", isUp, roundingMode)
	nearestIncrement, downIncrement := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %s\n", nearestIncrement, isNearest, nearest)
	fmt.Fprintf(c.b, "  %%%s = and i1 %s, %s\n", downIncrement, negative, nonzero)
	downSelected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", downSelected, isDown, downIncrement)
	nonnegative, upIncrement, upSelected := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", nonnegative, negative)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %s\n", upIncrement, nonnegative, nonzero)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", upSelected, isUp, upIncrement)
	combined, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", combined, nearestIncrement, downSelected)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", result, combined, upSelected)
	return "%" + result
}

func (c *amd64Ctx) emitReduceResult(laneBits int, sourceBits, finiteRoundedBits, isNaN, isInfinity, roundingMode string, quietBit, signBit uint64) string {
	floatType := "float"
	if laneBits == 64 {
		floatType = "double"
	}
	special := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", special, isNaN, isInfinity)
	safeSourceBits, safeRoundedBits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 0, i%d %s\n", safeSourceBits, special, laneBits, laneBits, sourceBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 0, i%d %s\n", safeRoundedBits, special, laneBits, laneBits, finiteRoundedBits)
	sourceFloat, roundedFloat := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %%%s to %s\n", sourceFloat, laneBits, safeSourceBits, floatType)
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %%%s to %s\n", roundedFloat, laneBits, safeRoundedBits, floatType)
	reducedFloat, reducedBits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fsub %s %%%s, %%%s\n", reducedFloat, floatType, sourceFloat, roundedFloat)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to i%d\n", reducedBits, floatType, reducedFloat, laneBits)
	reducedMagnitude, reducedZero := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", reducedMagnitude, laneBits, reducedBits, signBit-1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", reducedZero, laneBits, reducedMagnitude)
	isDown := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 1\n", isDown, roundingMode)
	zeroBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d 0\n", zeroBits, isDown, laneBits, signBit, laneBits)
	zeroAdjusted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", zeroAdjusted, reducedZero, laneBits, zeroBits, laneBits, reducedBits)
	withInfinity := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d 0, i%d %%%s\n", withInfinity, isInfinity, laneBits, laneBits, zeroAdjusted)
	quietNaNBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i%d %s, %d\n", quietNaNBits, laneBits, sourceBits, quietBit)
	final := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %%%s\n", final, isNaN, laneBits, quietNaNBits, laneBits, withInfinity)
	return "%" + final
}
