package plan9asm

import "fmt"

type x87PortableNumber struct {
	significand string
	unit        string
	negative    string
	zero        string
	infinite    string
	nan         string
	unsupported string
}

func (c *amd64Ctx) x87PortableDecode(value x87Value) x87PortableNumber {
	significand, signExponent := c.partsX87(value)
	exponent := c.x87PortableIR("and i16 %s, 32767", signExponent)
	zeroExponent := c.x87PortableIR("icmp eq i16 %s, 0", exponent)
	effective := c.x87PortableIR("select i1 %s, i16 1, i16 %s", zeroExponent, exponent)
	effective = c.x87PortableIR("zext i16 %s to i32", effective)
	unit := c.x87PortableIR("sub i32 %s, 16446", effective)
	negative := c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
	zero := c.x87PortableIR("icmp eq i64 %s, 0", significand)
	zero = c.x87PortableIR("and i1 %s, %s", zero, zeroExponent)
	special := c.x87PortableIR("icmp eq i16 %s, 32767", exponent)
	integerOnly := c.x87PortableIR("icmp eq i64 %s, 9223372036854775808", significand)
	infinite := c.x87PortableIR("and i1 %s, %s", special, integerOnly)
	payload := c.x87PortableIR("xor i1 %s, true", integerOnly)
	nan := c.x87PortableIR("and i1 %s, %s", special, payload)
	missingInteger := c.x87PortableIR("icmp sge i64 %s, 0", significand)
	nonzeroExponent := c.x87PortableIR("xor i1 %s, true", zeroExponent)
	unsupported := c.x87PortableIR("and i1 %s, %s", missingInteger, nonzeroExponent)
	return x87PortableNumber{significand, unit, negative, zero, infinite, nan, unsupported}
}

func (c *amd64Ctx) x87PortableChoose(condition string, first, second x87Value) x87Value {
	return x87Value(c.x87PortableIR("select i1 %s, %s %s, %s %s", condition, x87ValueType, first, x87ValueType, second))
}

func (c *amd64Ctx) x87PortableSignedZero(negative string) x87Value {
	sign := c.x87PortableIR("select i1 %s, i16 32768, i16 0", negative)
	return c.packX87("0", sign)
}

func (c *amd64Ctx) x87PortableInfinity(negative string) x87Value {
	exponent := c.x87PortableIR("select i1 %s, i16 65535, i16 32767", negative)
	return c.packX87("9223372036854775808", exponent)
}

func (c *amd64Ctx) x87PortableQuietNaN(value x87PortableNumber) x87Value {
	significand := c.x87PortableIR("or i64 %s, 13835058055282163712", value.significand)
	exponent := c.x87PortableIR("select i1 %s, i16 65535, i16 32767", value.negative)
	significand = c.x87PortableIR("select i1 %s, i64 13835058055282163712, i64 %s", value.unsupported, significand)
	exponent = c.x87PortableIR("select i1 %s, i16 65535, i16 %s", value.unsupported, exponent)
	return c.packX87(significand, exponent)
}

func (c *amd64Ctx) x87PortableAlign(magnitude, exponent, unit string) string {
	// Reuse the existing bounded integer align/jam primitive. Reserve its SSA
	// suffixes through the enclosing context when several operations share a block.
	emitter := amd64FMA3IntegerEmitter{b: c.b, next: c.tmp}
	result := emitter.align(magnitude, exponent, unit)
	c.tmp = emitter.next
	return result
}

func (c *amd64Ctx) x87PortableLeading128(value string) string {
	high := c.x87PortableIR("lshr i128 %s, 64", value)
	high = c.x87PortableIR("trunc i128 %s to i64", high)
	low := c.x87PortableIR("trunc i128 %s to i64", value)
	highZero := c.x87PortableIR("icmp eq i64 %s, 0", high)
	highCount := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", high)
	lowCount := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", low)
	lowCount = c.x87PortableIR("add i64 %s, 64", lowCount)
	leading := c.x87PortableIR("select i1 %s, i64 %s, i64 %s", highZero, lowCount, highCount)
	return c.x87PortableIR("trunc i64 %s to i32", leading)
}

// Round the exact integer magnitude at unit to a binary80 value. Precision is
// a significand width (24/53/64), independent of the explicit-integer storage
// format and its 15-bit exponent. PC=01 remains reserved/unqualified.
func (c *amd64Ctx) x87PortableRoundPack(magnitude, unit, negative, cw string) x87Value {
	pc := c.x87PortableIR("lshr i16 %s, 8", cw)
	pc = c.x87PortableIR("and i16 %s, 3", pc)
	pc24 := c.x87PortableIR("icmp eq i16 %s, 0", pc)
	pc53 := c.x87PortableIR("icmp eq i16 %s, 2", pc)
	precision := c.x87PortableIR("select i1 %s, i32 53, i32 64", pc53)
	precision = c.x87PortableIR("select i1 %s, i32 24, i32 %s", pc24, precision)
	leading := c.x87PortableLeading128(magnitude)
	highest := c.x87PortableIR("sub i32 127, %s", leading)
	normalShift := c.x87PortableIR("sub i32 %s, %s", highest, precision)
	normalShift = c.x87PortableIR("add i32 %s, 1", normalShift)
	minimumUnit := c.x87PortableIR("sub i32 -16381, %s", precision)
	minimumShift := c.x87PortableIR("sub i32 %s, %s", minimumUnit, unit)
	subnormal := c.x87PortableIR("icmp sgt i32 %s, %s", minimumShift, normalShift)
	shift := c.x87PortableIR("select i1 %s, i32 %s, i32 %s", subnormal, minimumShift, normalShift)
	rightward := c.x87PortableIR("icmp sgt i32 %s, 0", shift)
	far := c.x87PortableIR("icmp sge i32 %s, 128", shift)
	rightCount := c.x87PortableIR("select i1 %s, i32 %s, i32 0", rightward, shift)
	rightCount = c.x87PortableIR("select i1 %s, i32 127, i32 %s", far, rightCount)
	rightCount = c.x87PortableIR("zext i32 %s to i128", rightCount)
	right := c.x87PortableIR("lshr i128 %s, %s", magnitude, rightCount)
	right = c.x87PortableIR("select i1 %s, i128 0, i128 %s", far, right)
	leftCount := c.x87PortableIR("sub i32 0, %s", shift)
	leftCount = c.x87PortableIR("select i1 %s, i32 0, i32 %s", rightward, leftCount)
	leftFar := c.x87PortableIR("icmp ugt i32 %s, 127", leftCount)
	leftCount = c.x87PortableIR("select i1 %s, i32 127, i32 %s", leftFar, leftCount)
	leftCount = c.x87PortableIR("zext i32 %s to i128", leftCount)
	left := c.x87PortableIR("shl i128 %s, %s", magnitude, leftCount)
	unrounded := c.x87PortableIR("select i1 %s, i128 %s, i128 %s", rightward, right, left)
	mask := c.x87PortableIR("shl i128 1, %s", rightCount)
	mask = c.x87PortableIR("sub i128 %s, 1", mask)
	mask = c.x87PortableIR("select i1 %s, i128 -1, i128 %s", far, mask)
	remainder := c.x87PortableIR("and i128 %s, %s", magnitude, mask)
	inexact := c.x87PortableIR("icmp ne i128 %s, 0", remainder)
	halfCount := c.x87PortableIR("sub i32 %s, 1", shift)
	halfCount = c.x87PortableIR("select i1 %s, i32 %s, i32 0", rightward, halfCount)
	halfFar := c.x87PortableIR("icmp ugt i32 %s, 127", halfCount)
	halfCount = c.x87PortableIR("select i1 %s, i32 127, i32 %s", halfFar, halfCount)
	halfCount = c.x87PortableIR("zext i32 %s to i128", halfCount)
	half := c.x87PortableIR("shl i128 1, %s", halfCount)
	above := c.x87PortableIR("icmp ugt i128 %s, %s", remainder, half)
	tie := c.x87PortableIR("icmp eq i128 %s, %s", remainder, half)
	odd := c.x87PortableIR("and i128 %s, 1", unrounded)
	oddBit := c.x87PortableIR("icmp ne i128 %s, 0", odd)
	tie = c.x87PortableIR("and i1 %s, %s", tie, oddBit)
	nearest := c.x87PortableIR("or i1 %s, %s", above, tie)
	validHalf := c.x87PortableIR("xor i1 %s, true", halfFar)
	validHalf = c.x87PortableIR("and i1 %s, %s", validHalf, rightward)
	nearest = c.x87PortableIR("and i1 %s, %s", nearest, validHalf)
	rc := c.x87PortableIR("lshr i16 %s, 10", cw)
	rc = c.x87PortableIR("and i16 %s, 3", rc)
	isNearest := c.x87PortableIR("icmp eq i16 %s, 0", rc)
	down := c.x87PortableIR("icmp eq i16 %s, 1", rc)
	up := c.x87PortableIR("icmp eq i16 %s, 2", rc)
	positive := c.x87PortableIR("xor i1 %s, true", negative)
	down = c.x87PortableIR("and i1 %s, %s", down, negative)
	up = c.x87PortableIR("and i1 %s, %s", up, positive)
	away := c.x87PortableIR("or i1 %s, %s", down, up)
	directed := c.x87PortableIR("and i1 %s, %s", away, inexact)
	increment := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", isNearest, nearest, directed)
	increment = c.x87PortableIR("zext i1 %s to i128", increment)
	rounded := c.x87PortableIR("add i128 %s, %s", unrounded, increment)
	precision128 := c.x87PortableIR("zext i32 %s to i128", precision)
	carryLimit := c.x87PortableIR("shl i128 1, %s", precision128)
	carry := c.x87PortableIR("icmp uge i128 %s, %s", rounded, carryLimit)
	shrunk := c.x87PortableIR("lshr i128 %s, 1", rounded)
	rounded = c.x87PortableIR("select i1 %s, i128 %s, i128 %s", carry, shrunk, rounded)
	exponent := c.x87PortableIR("add i32 %s, %s", unit, shift)
	exponent = c.x87PortableIR("add i32 %s, %s", exponent, precision)
	exponent = c.x87PortableIR("add i32 %s, 16382", exponent)
	carry32 := c.x87PortableIR("zext i1 %s to i32", carry)
	exponent = c.x87PortableIR("add i32 %s, %s", exponent, carry32)
	storageShift := c.x87PortableIR("sub i32 64, %s", precision)
	storageShift128 := c.x87PortableIR("zext i32 %s to i128", storageShift)
	stored := c.x87PortableIR("shl i128 %s, %s", rounded, storageShift128)
	significand := c.x87PortableIR("trunc i128 %s to i64", stored)
	integerMissing := c.x87PortableIR("icmp sge i64 %s, 0", significand)
	exponent = c.x87PortableIR("select i1 %s, i32 0, i32 %s", integerMissing, exponent)
	overflow := c.x87PortableIR("icmp sge i32 %s, 32767", exponent)
	toInfinity := c.x87PortableIR("or i1 %s, %s", isNearest, away)
	maximum := c.x87PortableIR("sub i128 %s, 1", carryLimit)
	maximum = c.x87PortableIR("shl i128 %s, %s", maximum, storageShift128)
	maximum64 := c.x87PortableIR("trunc i128 %s to i64", maximum)
	overflowSig := c.x87PortableIR("select i1 %s, i64 9223372036854775808, i64 %s", toInfinity, maximum64)
	overflowExp := c.x87PortableIR("select i1 %s, i32 32767, i32 32766", toInfinity)
	significand = c.x87PortableIR("select i1 %s, i64 %s, i64 %s", overflow, overflowSig, significand)
	exponent = c.x87PortableIR("select i1 %s, i32 %s, i32 %s", overflow, overflowExp, exponent)
	exponent16 := c.x87PortableIR("trunc i32 %s to i16", exponent)
	sign := c.x87PortableIR("select i1 %s, i16 32768, i16 0", negative)
	exponent16 = c.x87PortableIR("or i16 %s, %s", exponent16, sign)
	return c.packX87(significand, exponent16)
}

func (c *amd64Ctx) x87PortableAddSubtract(left, right x87PortableNumber, subtract bool, cw string) x87Value {
	rightNegative := right.negative
	if subtract {
		rightNegative = c.x87PortableIR("xor i1 %s, true", rightNegative)
	}
	largerExponent := c.x87PortableIR("icmp sgt i32 %s, %s", left.unit, right.unit)
	unit := c.x87PortableIR("select i1 %s, i32 %s, i32 %s", largerExponent, left.unit, right.unit)
	unit = c.x87PortableIR("sub i32 %s, 3", unit)
	a := c.x87PortableIR("zext i64 %s to i128", left.significand)
	b := c.x87PortableIR("zext i64 %s to i128", right.significand)
	a = c.x87PortableAlign(a, left.unit, unit)
	b = c.x87PortableAlign(b, right.unit, unit)
	sameSign := c.x87PortableIR("icmp eq i1 %s, %s", left.negative, rightNegative)
	larger := c.x87PortableIR("icmp uge i128 %s, %s", a, b)
	sum := c.x87PortableIR("add i128 %s, %s", a, b)
	difference := c.x87PortableIR("sub i128 %s, %s", a, b)
	reverse := c.x87PortableIR("sub i128 %s, %s", b, a)
	difference = c.x87PortableIR("select i1 %s, i128 %s, i128 %s", larger, difference, reverse)
	magnitude := c.x87PortableIR("select i1 %s, i128 %s, i128 %s", sameSign, sum, difference)
	negative := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", larger, left.negative, rightNegative)
	zero := c.x87PortableIR("icmp eq i128 %s, 0", magnitude)
	down := c.x87PortableIR("and i16 %s, 3072", cw)
	down = c.x87PortableIR("icmp eq i16 %s, 1024", down)
	zeroSign := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", sameSign, left.negative, down)
	negative = c.x87PortableIR("select i1 %s, i1 %s, i1 %s", zero, zeroSign, negative)
	return c.x87PortableRoundPack(magnitude, unit, negative, cw)
}

func (c *amd64Ctx) x87PortableDivide(left, right x87PortableNumber, cw string) x87Value {
	aLeading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", left.significand)
	bLeading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", right.significand)
	aShift := c.x87PortableIR("and i64 %s, 63", aLeading)
	bShift := c.x87PortableIR("and i64 %s, 63", bLeading)
	a := c.x87PortableIR("zext i64 %s to i128", left.significand)
	b := c.x87PortableIR("zext i64 %s to i128", right.significand)
	aShift128 := c.x87PortableIR("zext i64 %s to i128", aShift)
	bShift128 := c.x87PortableIR("zext i64 %s to i128", bShift)
	a = c.x87PortableIR("shl i128 %s, %s", a, aShift128)
	b = c.x87PortableIR("shl i128 %s, %s", b, bShift128)
	aTop := c.x87PortableIR("add i32 %s, 63", left.unit)
	bTop := c.x87PortableIR("add i32 %s, 63", right.unit)
	aLeading32 := c.x87PortableIR("trunc i64 %s to i32", aLeading)
	bLeading32 := c.x87PortableIR("trunc i64 %s to i32", bLeading)
	aTop = c.x87PortableIR("sub i32 %s, %s", aTop, aLeading32)
	bTop = c.x87PortableIR("sub i32 %s, %s", bTop, bLeading32)
	exponent := c.x87PortableIR("sub i32 %s, %s", aTop, bTop)
	belowOne := c.x87PortableIR("icmp ult i128 %s, %s", a, b)
	doubled := c.x87PortableIR("shl i128 %s, 1", a)
	a = c.x87PortableIR("select i1 %s, i128 %s, i128 %s", belowOne, doubled, a)
	correction := c.x87PortableIR("zext i1 %s to i32", belowOne)
	exponent = c.x87PortableIR("sub i32 %s, %s", exponent, correction)
	unit := c.x87PortableIR("sub i32 %s, 66", exponent)
	initial := c.x87PortableIR("sub i128 %s, %s", a, b)
	identifier := c.newTmp()
	prepare, loop, done := "x87_div_prepare_"+identifier, "x87_div_loop_"+identifier, "x87_div_done_"+identifier
	quotient, remainder, iteration := c.newTmp(), c.newTmp(), c.newTmp()
	nextQuotient, nextRemainder, nextIteration := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  br label %%%s\n%s:\n  br label %%%s\n%s:\n", prepare, prepare, loop, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i128 [ 1, %%%s ], [ %%%s, %%%s ]\n", quotient, prepare, nextQuotient, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i128 [ %s, %%%s ], [ %%%s, %%%s ]\n", remainder, initial, prepare, nextRemainder, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i32 [ 0, %%%s ], [ %%%s, %%%s ]\n", iteration, prepare, nextIteration, loop)
	doubledRemainder := c.x87PortableIR("shl i128 %%%s, 1", remainder)
	bit := c.x87PortableIR("icmp uge i128 %s, %s", doubledRemainder, b)
	subtracted := c.x87PortableIR("sub i128 %s, %s", doubledRemainder, b)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i128 %s, i128 %s\n", nextRemainder, bit, subtracted, doubledRemainder)
	shiftedQuotient := c.x87PortableIR("shl i128 %%%s, 1", quotient)
	bit128 := c.x87PortableIR("zext i1 %s to i128", bit)
	fmt.Fprintf(c.b, "  %%%s = or i128 %s, %s\n", nextQuotient, shiftedQuotient, bit128)
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, 1\n", nextIteration, iteration)
	finished := c.x87PortableIR("icmp eq i32 %%%s, 66", nextIteration)
	fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", finished, done, loop, done)
	sticky := c.x87PortableIR("icmp ne i128 %%%s, 0", nextRemainder)
	sticky = c.x87PortableIR("zext i1 %s to i128", sticky)
	magnitude := c.x87PortableIR("or i128 %%%s, %s", nextQuotient, sticky)
	negative := c.x87PortableIR("xor i1 %s, %s", left.negative, right.negative)
	return c.x87PortableRoundPack(magnitude, unit, negative, cw)
}

func (c *amd64Ctx) x87PortableBinary(operation string, left, right x87Value, cw string) (x87Value, error) {
	if operation != "fadd" && operation != "fsub" && operation != "fmul" && operation != "fdiv" {
		return "", fmt.Errorf("unsupported portable x87 arithmetic %s", operation)
	}
	a, b := c.x87PortableDecode(left), c.x87PortableDecode(right)
	negative := c.x87PortableIR("xor i1 %s, %s", a.negative, b.negative)
	var result x87Value
	if operation == "fadd" || operation == "fsub" {
		result = c.x87PortableAddSubtract(a, b, operation == "fsub", cw)
	} else if operation == "fdiv" {
		result = c.x87PortableDivide(a, b, cw)
	} else {
		first := c.x87PortableIR("zext i64 %s to i128", a.significand)
		second := c.x87PortableIR("zext i64 %s to i128", b.significand)
		product := c.x87PortableIR("mul i128 %s, %s", first, second)
		unit := c.x87PortableIR("add i32 %s, %s", a.unit, b.unit)
		result = c.x87PortableRoundPack(product, unit, negative, cw)
	}
	indefinite := c.packX87("13835058055282163712", "65535")
	if operation == "fadd" || operation == "fsub" {
		rightNegative := b.negative
		if operation == "fsub" {
			rightNegative = c.x87PortableIR("xor i1 %s, true", rightNegative)
		}
		anyInf := c.x87PortableIR("or i1 %s, %s", a.infinite, b.infinite)
		infinitySign := c.x87PortableIR("select i1 %s, i1 %s, i1 %s", a.infinite, a.negative, rightNegative)
		result = c.x87PortableChoose(anyInf, c.x87PortableInfinity(infinitySign), result)
		bothInf := c.x87PortableIR("and i1 %s, %s", a.infinite, b.infinite)
		differentSign := c.x87PortableIR("xor i1 %s, %s", a.negative, rightNegative)
		invalid := c.x87PortableIR("and i1 %s, %s", bothInf, differentSign)
		result = c.x87PortableChoose(invalid, indefinite, result)
	} else {
		anyZero := c.x87PortableIR("or i1 %s, %s", a.zero, b.zero)
		anyInf := c.x87PortableIR("or i1 %s, %s", a.infinite, b.infinite)
		invalid := c.x87PortableIR("and i1 %s, %s", a.infinite, b.zero)
		otherInvalid := c.x87PortableIR("and i1 %s, %s", b.infinite, a.zero)
		if operation == "fdiv" {
			invalid = c.x87PortableIR("and i1 %s, %s", a.infinite, b.infinite)
			otherInvalid = c.x87PortableIR("and i1 %s, %s", a.zero, b.zero)
			result = c.x87PortableChoose(b.infinite, c.x87PortableSignedZero(negative), result)
			result = c.x87PortableChoose(a.zero, c.x87PortableSignedZero(negative), result)
			infinite := c.x87PortableIR("or i1 %s, %s", a.infinite, b.zero)
			result = c.x87PortableChoose(infinite, c.x87PortableInfinity(negative), result)
		} else {
			result = c.x87PortableChoose(anyZero, c.x87PortableSignedZero(negative), result)
			result = c.x87PortableChoose(anyInf, c.x87PortableInfinity(negative), result)
		}
		invalid = c.x87PortableIR("or i1 %s, %s", invalid, otherInvalid)
		result = c.x87PortableChoose(invalid, indefinite, result)
	}
	invalidA := c.x87PortableIR("or i1 %s, %s", a.nan, a.unsupported)
	invalidB := c.x87PortableIR("or i1 %s, %s", b.nan, b.unsupported)
	anyNaN := c.x87PortableIR("or i1 %s, %s", invalidA, invalidB)
	// Among supported NaNs, compare the original significands before quieting.
	// The quiet bit makes a QNaN dominate an SNaN; equal payload/significand
	// ties choose the positive sign. Unsupported encodings keep their separate
	// existing invalid-value path rather than entering this payload ordering.
	bothNaN := c.x87PortableIR("and i1 %s, %s", a.nan, b.nan)
	unsupported := c.x87PortableIR("or i1 %s, %s", a.unsupported, b.unsupported)
	supported := c.x87PortableIR("xor i1 %s, true", unsupported)
	bothNaN = c.x87PortableIR("and i1 %s, %s", bothNaN, supported)
	larger := c.x87PortableIR("icmp ugt i64 %s, %s", a.significand, b.significand)
	equal := c.x87PortableIR("icmp eq i64 %s, %s", a.significand, b.significand)
	positive := c.x87PortableIR("xor i1 %s, true", a.negative)
	positiveTie := c.x87PortableIR("and i1 %s, %s", equal, positive)
	preferA := c.x87PortableIR("or i1 %s, %s", larger, positiveTie)
	preferA = c.x87PortableIR("select i1 %s, i1 %s, i1 %s", bothNaN, preferA, invalidA)
	selectedNaN := c.x87PortableChoose(preferA, c.x87PortableQuietNaN(a), c.x87PortableQuietNaN(b))
	return c.x87PortableChoose(anyNaN, selectedNaN, result), nil
}
