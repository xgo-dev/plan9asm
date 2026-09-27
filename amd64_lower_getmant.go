package plan9asm

import (
	"fmt"
	"strings"
)

type amd64GetMantSpec = amd64UnaryImmediateFloatingShape

var amd64GetMantSpecs = map[Op]amd64GetMantSpec{
	"VGETMANTPS": {laneBits: 32},
	"VGETMANTPD": {laneBits: 64},
	"VGETMANTSS": {laneBits: 32, scalar: true},
	"VGETMANTSD": {laneBits: 64, scalar: true},
}

func (c *amd64Ctx) lowerGetMant(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64GetMantSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	form, err := c.parseUnaryImmediateFloatingForm(baseOp, suffix, spec, ins)
	if err != nil {
		return true, false, err
	}
	daz := c.loadMXCSRDAZ()
	if spec.scalar {
		return c.lowerScalarGetMant(spec, form.properties, form.source, form.passthrough, form.destination, form.mask, daz, form.immediate)
	}
	return c.lowerPackedGetMant(spec, form.properties, form.source, form.destination, form.byteWidth, form.mask, daz, form.immediate)
}

func (c *amd64Ctx) lowerPackedGetMant(spec amd64GetMantSpec, properties amd64BinaryFloatingSuffix, source, destination Operand, byteWidth int, mask, daz string, immediate uint8) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	input, err := c.loadPackedCompareLanes(source, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	result := c.emitGetMantBits(lanes, spec.laneBits, input, daz, immediate)
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

func (c *amd64Ctx) lowerScalarGetMant(spec amd64GetMantSpec, properties amd64BinaryFloatingSuffix, source, passthrough, destination Operand, mask, daz string, immediate uint8) (bool, bool, error) {
	sourceBits, err := c.loadFloatingScalarBits(source, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", input, spec.laneBits, spec.laneBits, sourceBits)
	result := c.emitGetMantBits(1, spec.laneBits, "%"+input, daz, immediate)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	passthroughBytes, err := c.loadX(passthrough.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, passthroughBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+low, base, mask, properties.zeroing)
}

func (c *amd64Ctx) emitGetMantBits(lanes, laneBits int, input, daz string, immediate uint8) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	mantissaBits, bias := 23, 127
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	signBit := uint64(0x80000000)
	indefinite := uint64(0xffc00000)
	if laneBits == 64 {
		mantissaBits, bias = 52, 1023
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
		signBit = uint64(0x8000000000000000)
		indefinite = uint64(0xfff8000000000000)
	}
	interval := immediate & 3
	signControl := immediate >> 2 & 3
	positiveOne := uint64(bias) << mantissaBits
	signedOne := positiveOne
	if signControl&1 == 0 {
		signedOne |= signBit
	}
	dazClear := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i1 %s, false\n", dazClear, daz)
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		bits, exponent, mantissa, sign := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", bits, vectorType, input, lane)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", exponent, laneBits, bits, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", mantissa, laneBits, bits, mantissaMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", sign, laneBits, bits, signBit)
		exponentZero, exponentOnes := c.newTmp(), c.newTmp()
		mantissaZero, mantissaNonzero, negative := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", exponentZero, laneBits, exponent)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", exponentOnes, laneBits, exponent, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", mantissaZero, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", mantissaNonzero, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", negative, laneBits, sign)
		isNaN, isInfinity, isDenormal := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isNaN, exponentOnes, mantissaNonzero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isInfinity, exponentOnes, mantissaZero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isDenormal, exponentZero, mantissaNonzero)
		activeDenormal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", activeDenormal, isDenormal, dazClear)
		zeroOrDAZ, effectiveZero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", zeroOrDAZ, mantissaZero, daz)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", effectiveZero, exponentZero, zeroOrDAZ)

		leadingZeros, shiftCount, shifted, normalizedFraction := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.ctlz.i%d(i%d %%%s, i1 false)\n", leadingZeros, laneBits, laneBits, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, %d\n", shiftCount, laneBits, leadingZeros, laneBits-mantissaBits-1)
		fmt.Fprintf(c.b, "  %%%s = shl i%d %%%s, %%%s\n", shifted, laneBits, mantissa, shiftCount)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", normalizedFraction, laneBits, shifted, mantissaMask)
		fraction := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", fraction, activeDenormal, laneBits, normalizedFraction, laneBits, mantissa)
		exponentField, unbiasedNormal, unbiasedDenormal, unbiased := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %d\n", exponentField, laneBits, exponent, mantissaBits)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, %d\n", unbiasedNormal, laneBits, exponentField, bias)
		fmt.Fprintf(c.b, "  %%%s = sub i%d 0, %%%s\n", unbiasedDenormal, laneBits, shiftCount)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", unbiased, activeDenormal, laneBits, unbiasedDenormal, laneBits, unbiasedNormal)
		oddValue, odd := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, 1\n", oddValue, laneBits, unbiased)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", odd, laneBits, oddValue)
		fractionTop, topSet := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", fractionTop, laneBits, fraction, quietBit)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", topSet, laneBits, fractionTop)
		normalizedExponent := fmt.Sprintf("%d", bias)
		switch interval {
		case 1:
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %d\n", selected, odd, laneBits, bias-1, laneBits, bias)
			normalizedExponent = "%" + selected
		case 2:
			normalizedExponent = fmt.Sprintf("%d", bias-1)
		case 3:
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %d\n", selected, topSet, laneBits, bias-1, laneBits, bias)
			normalizedExponent = "%" + selected
		}
		exponentBits, magnitude := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i%d %s, %d\n", exponentBits, laneBits, normalizedExponent, mantissaBits)
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %%%s\n", magnitude, laneBits, exponentBits, fraction)
		computed := "%" + magnitude
		if signControl&1 == 0 {
			withSign := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %%%s\n", withSign, laneBits, magnitude, sign)
			computed = "%" + withSign
		}
		zeroOrInfinity := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", zeroOrInfinity, effectiveZero, isInfinity)
		specialOne := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %d\n", specialOne, negative, laneBits, signedOne, laneBits, positiveOne)
		withSpecial := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %s\n", withSpecial, zeroOrInfinity, laneBits, specialOne, laneBits, computed)
		selected := "%" + withSpecial
		if signControl&2 != 0 {
			notZero := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notZero, effectiveZero)
			nonzeroNegative := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", nonzeroNegative, negative, notZero)
			indefiniteResult := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %s\n", indefiniteResult, nonzeroNegative, laneBits, indefinite, laneBits, selected)
			selected = "%" + indefiniteResult
		}
		quietNaN := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", quietNaN, laneBits, bits, quietBit)
		final := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %s\n", final, isNaN, laneBits, quietNaN, laneBits, selected)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, result, laneBits, final, lane)
		result = "%" + inserted
	}
	return result
}
