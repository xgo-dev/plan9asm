package plan9asm

import (
	"fmt"
	"strings"
)

// Fixed rounding with SAE must not perform ambient floating arithmetic: LLVM
// may lower constrained operations to libcalls, and even a corrected result
// cannot undo a hardware exception. All arithmetic below is integer-only.
// A finite product is exact in 106 bits. Division generates p+3 quotient bits
// by bounded restoring division and jams the remaining exact remainder.
// The private ABI carries raw i32/i64 bits, never float/double. Otherwise an
// un-inlined mode32 C return would use x87 and could change exception state.
func emitX86FloatMulDivRoundingHelper(b *strings.Builder, bits int) {
	fractionBits, bias := 23, 127
	if bits == 64 {
		fractionBits, bias = 52, 1023
	}
	typ := amd64FMA3LLVMType(1, bits)
	infBits := uint64(2*bias+1) << fractionBits
	signBit := uint64(1) << (bits - 1)
	quietBit := uint64(1) << (fractionBits - 1)

	fmt.Fprintf(b, "define internal i%d @__plan9asm_mul_div_round_f%d(i%d %%left, i%d %%right, i1 %%divide, i32 %%mode, i32 %%mxcsr) {\nentry:\n", bits, bits, bits, bits)
	e := amd64FMA3IntegerEmitter{b: b}
	daz := e.value("and i32 %%mxcsr, 64")
	daz = e.value("icmp ne i32 %s, 0", daz)
	leftValue := e.value("bitcast i%d %%left to %s", bits, typ)
	rightValue := e.value("bitcast i%d %%right to %s", bits, typ)
	left, right := e.input(bits, leftValue, daz), e.input(bits, rightValue, daz)

	// NaNs retain source priority and payload; invalid non-NaN operations
	// produce the architecture's negative quiet indefinite value.
	a := e.value("bitcast %s %s to i%d", typ, left.floating, bits)
	bb := e.value("bitcast %s %s to i%d", typ, right.floating, bits)
	aAbs := e.value("and i%d %s, %d", bits, a, signBit-1)
	bAbs := e.value("and i%d %s, %d", bits, bb, signBit-1)
	aNaN := e.value("icmp ugt i%d %s, %d", bits, aAbs, infBits)
	bNaN := e.value("icmp ugt i%d %s, %d", bits, bAbs, infBits)
	anyNaN := e.value("or i1 %s, %s", aNaN, bNaN)
	selectedNaN := e.value("select i1 %s, i%d %s, i%d %s", aNaN, bits, a, bits, bb)
	selectedNaN = e.value("or i%d %s, %d", bits, selectedNaN, quietBit)
	aInf := e.value("icmp eq i%d %s, %d", bits, aAbs, infBits)
	bInf := e.value("icmp eq i%d %s, %d", bits, bAbs, infBits)
	aZero := e.value("icmp eq i128 %s, 0", left.magnitude)
	bZero := e.value("icmp eq i128 %s, 0", right.magnitude)
	negative := e.value("xor i1 %s, %s", left.negative, right.negative)
	sign := e.value("select i1 %s, i%d %d, i%d 0", negative, bits, signBit, bits)
	signedInf := e.value("or i%d %s, %d", bits, sign, infBits)
	invalidMulA := e.value("and i1 %s, %s", aInf, bZero)
	invalidMulB := e.value("and i1 %s, %s", bInf, aZero)
	invalidMul := e.value("or i1 %s, %s", invalidMulA, invalidMulB)
	invalidDivA := e.value("and i1 %s, %s", aInf, bInf)
	invalidDivB := e.value("and i1 %s, %s", aZero, bZero)
	invalidDiv := e.value("or i1 %s, %s", invalidDivA, invalidDivB)
	invalid := e.value("select i1 %%divide, i1 %s, i1 %s", invalidDiv, invalidMul)
	anyInf := e.value("or i1 %s, %s", aInf, bInf)
	anyZero := e.value("or i1 %s, %s", aZero, bZero)
	divInf := e.value("or i1 %s, %s", aInf, bZero)
	resultInf := e.value("select i1 %%divide, i1 %s, i1 %s", divInf, anyInf)
	special := e.value("or i1 %s, %s", anyInf, anyZero)
	special = e.value("or i1 %s, %s", special, anyNaN)
	encoded := e.value("select i1 %s, i%d %s, i%d %s", resultInf, bits, signedInf, bits, sign)
	encoded = e.value("select i1 %s, i%d %d, i%d %s", invalid, bits, signBit|infBits|quietBit, bits, encoded)
	encoded = e.value("select i1 %s, i%d %s, i%d %s", anyNaN, bits, selectedNaN, bits, encoded)
	fmt.Fprintf(b, "  br i1 %s, label %%special, label %%finite\nspecial:\n", special)
	fmt.Fprintf(b, "  ret i%d %s\nfinite:\n  br i1 %%divide, label %%division_prepare, label %%multiply\nmultiply:\n", bits, encoded)
	product := e.value("mul i128 %s, %s", left.magnitude, right.magnitude)
	productUnit := e.value("add i32 %s, %s", left.exponent, right.exponent)

	// Normalize both finite nonzero significands to the same leading bit.
	b.WriteString("  br label %round\ndivision_prepare:\n")
	aLeading := e.value("call i128 @llvm.ctlz.i128(i128 %s, i1 false)", left.magnitude)
	bLeading := e.value("call i128 @llvm.ctlz.i128(i128 %s, i1 false)", right.magnitude)
	aLeading = e.value("trunc i128 %s to i32", aLeading)
	bLeading = e.value("trunc i128 %s to i32", bLeading)
	aHighest := e.value("sub i32 127, %s", aLeading)
	bHighest := e.value("sub i32 127, %s", bLeading)
	aShift := e.value("sub i32 %d, %s", fractionBits, aHighest)
	bShift := e.value("sub i32 %d, %s", fractionBits, bHighest)
	aShift = e.value("zext i32 %s to i128", aShift)
	bShift = e.value("zext i32 %s to i128", bShift)
	numerator := e.value("shl i128 %s, %s", left.magnitude, aShift)
	denominator := e.value("shl i128 %s, %s", right.magnitude, bShift)
	aTop := e.value("add i32 %s, %s", left.exponent, aHighest)
	bTop := e.value("add i32 %s, %s", right.exponent, bHighest)
	ratioExponent := e.value("sub i32 %s, %s", aTop, bTop)
	belowOne := e.value("icmp ult i128 %s, %s", numerator, denominator)
	doubled := e.value("shl i128 %s, 1", numerator)
	numerator = e.value("select i1 %s, i128 %s, i128 %s", belowOne, doubled, numerator)
	exponentCorrection := e.value("zext i1 %s to i32", belowOne)
	ratioExponent = e.value("sub i32 %s, %s", ratioExponent, exponentCorrection)
	quotientUnit := e.value("sub i32 %s, %d", ratioExponent, fractionBits+3)
	initialRemainder := e.value("sub i128 %s, %s", numerator, denominator)

	// numerator is in [denominator, 2*denominator). Each iteration keeps
	// remainder in [0, denominator), emitting exactly one quotient bit.
	b.WriteString("  br label %division_loop\ndivision_loop:\n")
	b.WriteString("  %quotient = phi i128 [ 1, %division_prepare ], [ %next_quotient, %division_loop ]\n")
	fmt.Fprintf(b, "  %%remainder = phi i128 [ %s, %%division_prepare ], [ %%next_remainder, %%division_loop ]\n", initialRemainder)
	b.WriteString("  %iteration = phi i32 [ 0, %division_prepare ], [ %next_iteration, %division_loop ]\n")
	doubledRemainder := e.value("shl i128 %%remainder, 1")
	quotientBit := e.value("icmp uge i128 %s, %s", doubledRemainder, denominator)
	subtracted := e.value("sub i128 %s, %s", doubledRemainder, denominator)
	fmt.Fprintf(b, "  %%next_remainder = select i1 %s, i128 %s, i128 %s\n", quotientBit, subtracted, doubledRemainder)
	shiftedQuotient := e.value("shl i128 %%quotient, 1")
	bit128 := e.value("zext i1 %s to i128", quotientBit)
	fmt.Fprintf(b, "  %%next_quotient = or i128 %s, %s\n", shiftedQuotient, bit128)
	b.WriteString("  %next_iteration = add i32 %iteration, 1\n")
	done := e.value("icmp eq i32 %%next_iteration, %d", fractionBits+3)
	fmt.Fprintf(b, "  br i1 %s, label %%division_done, label %%division_loop\ndivision_done:\n", done)
	sticky := e.value("icmp ne i128 %%next_remainder, 0")
	sticky = e.value("zext i1 %s to i128", sticky)
	jammed := e.value("or i128 %%next_quotient, %s", sticky)

	b.WriteString("  br label %round\nround:\n")
	magnitude := e.value("phi i128 [ %s, %%multiply ], [ %s, %%division_done ]", product, jammed)
	unit := e.value("phi i32 [ %s, %%multiply ], [ %s, %%division_done ]", productUnit, quotientUnit)
	emitX86FloatMulDivRoundPack(&e, bits, magnitude, unit, negative)
}

// magnitude is nonzero. Multiplication retains its exact integer significand;
// division retains three guard bits plus jammed remainder. Clamp every shift
// before emission, including inactive select arms, so no LLVM poison is used.
func emitX86FloatMulDivRoundPack(e *amd64FMA3IntegerEmitter, bits int, magnitude, unit, negative string) {
	fractionBits, bias := 23, 127
	if bits == 64 {
		fractionBits, bias = 52, 1023
	}

	leading := e.value("call i128 @llvm.ctlz.i128(i128 %s, i1 false)", magnitude)
	leading = e.value("trunc i128 %s to i32", leading)
	highest := e.value("sub i32 127, %s", leading)
	normalShift := e.value("sub i32 %s, %d", highest, fractionBits)
	subnormalShift := e.value("sub i32 %d, %s", 1-bias-fractionBits, unit)
	isSubnormal := e.value("icmp sgt i32 %s, %s", subnormalShift, normalShift)
	shift := e.value("select i1 %s, i32 %s, i32 %s", isSubnormal, subnormalShift, normalShift)
	positiveShift := e.value("icmp sgt i32 %s, 0", shift)
	far := e.value("icmp sge i32 %s, 128", shift)
	safeRight := e.value("select i1 %s, i32 %s, i32 0", positiveShift, shift)
	safeRight = e.value("select i1 %s, i32 127, i32 %s", far, safeRight)
	safeRight = e.value("zext i32 %s to i128", safeRight)
	right := e.value("lshr i128 %s, %s", magnitude, safeRight)
	right = e.value("select i1 %s, i128 0, i128 %s", far, right)
	leftCount := e.value("sub i32 0, %s", shift)
	leftCount = e.value("select i1 %s, i32 0, i32 %s", positiveShift, leftCount)
	leftFar := e.value("icmp ugt i32 %s, 127", leftCount)
	leftCount = e.value("select i1 %s, i32 127, i32 %s", leftFar, leftCount)
	leftCount = e.value("zext i32 %s to i128", leftCount)
	left := e.value("shl i128 %s, %s", magnitude, leftCount)
	unrounded := e.value("select i1 %s, i128 %s, i128 %s", positiveShift, right, left)

	mask := e.value("shl i128 1, %s", safeRight)
	mask = e.value("sub i128 %s, 1", mask)
	remainder := e.value("and i128 %s, %s", magnitude, mask)
	remainder = e.value("select i1 %s, i128 %s, i128 %s", far, magnitude, remainder)
	inexact := e.value("icmp ne i128 %s, 0", remainder)
	halfCount := e.value("sub i32 %s, 1", shift)
	halfCount = e.value("select i1 %s, i32 %s, i32 0", positiveShift, halfCount)
	halfFar := e.value("icmp ugt i32 %s, 127", halfCount)
	halfCount = e.value("select i1 %s, i32 127, i32 %s", halfFar, halfCount)
	halfCount = e.value("zext i32 %s to i128", halfCount)
	half := e.value("shl i128 1, %s", halfCount)
	above := e.value("icmp ugt i128 %s, %s", remainder, half)
	tied := e.value("icmp eq i128 %s, %s", remainder, half)
	odd := e.value("and i128 %s, 1", unrounded)
	odd = e.value("icmp ne i128 %s, 0", odd)
	tied = e.value("and i1 %s, %s", tied, odd)
	nearest := e.value("or i1 %s, %s", above, tied)
	validHalf := e.value("xor i1 %s, true", halfFar)
	validHalf = e.value("and i1 %s, %s", validHalf, positiveShift)
	nearest = e.value("and i1 %s, %s", nearest, validHalf)
	downward := e.value("icmp eq i32 %%mode, 1")
	upward := e.value("icmp eq i32 %%mode, 2")
	positive := e.value("xor i1 %s, true", negative)
	directed := e.value("and i1 %s, %s", downward, negative)
	upwardPositive := e.value("and i1 %s, %s", upward, positive)
	directed = e.value("or i1 %s, %s", directed, upwardPositive)
	awayFromZero := directed
	directed = e.value("and i1 %s, %s", directed, inexact)
	isNearest := e.value("icmp eq i32 %%mode, 0")
	increment := e.value("select i1 %s, i1 %s, i1 %s", isNearest, nearest, directed)
	increment = e.value("zext i1 %s to i128", increment)
	rounded := e.value("add i128 %s, %s", unrounded, increment)

	carry := e.value("icmp uge i128 %s, %d", rounded, uint64(1)<<(fractionBits+1))
	carried := e.value("lshr i128 %s, 1", rounded)
	rounded = e.value("select i1 %s, i128 %s, i128 %s", carry, carried, rounded)
	carry32 := e.value("zext i1 %s to i32", carry)
	exponent := e.value("add i32 %s, %s", unit, shift)
	exponent = e.value("add i32 %s, %d", exponent, fractionBits+bias)
	exponent = e.value("add i32 %s, %s", exponent, carry32)
	stillSubnormal := e.value("icmp ult i128 %s, %d", rounded, uint64(1)<<fractionBits)
	exponent = e.value("select i1 %s, i32 0, i32 %s", stillSubnormal, exponent)
	encodedExponent := exponent
	if bits == 64 {
		encodedExponent = e.value("zext i32 %s to i64", exponent)
	}
	encodedExponent = e.value("shl i%d %s, %d", bits, encodedExponent, fractionBits)
	fraction := e.value("trunc i128 %s to i%d", rounded, bits)
	fraction = e.value("and i%d %s, %d", bits, fraction, uint64(1)<<fractionBits-1)
	encoded := e.value("or i%d %s, %s", bits, encodedExponent, fraction)
	overflow := e.value("icmp sge i32 %s, %d", exponent, 2*bias+1)
	toInfinity := e.value("or i1 %s, %s", isNearest, awayFromZero)
	infBits := uint64(2*bias+1) << fractionBits
	overflowBits := e.value("select i1 %s, i%d %d, i%d %d", toInfinity, bits, infBits, bits, infBits-1)
	encoded = e.value("select i1 %s, i%d %s, i%d %s", overflow, bits, overflowBits, bits, encoded)

	ftz := e.value("and i32 %%mxcsr, 32768")
	ftz = e.value("icmp ne i32 %s, 0", ftz)
	// Intel SDM 4.9.1.5 detects tininess after rounding with an unbounded
	// exponent, not after the additional rounding onto the subnormal grid.
	// Thus minimum-normal/(1+ulp), RU, is tiny, while maximum-subnormal
	// *(1+ulp), RN or RU, rounds to a normal unbounded-exponent result.
	tiny := emitX86FloatMulDivUnboundedTiny(e, fractionBits, bias, magnitude, normalShift, highest, unit, isNearest, awayFromZero)
	flush := e.value("and i1 %s, %s", ftz, tiny)
	encoded = e.value("select i1 %s, i%d 0, i%d %s", flush, bits, bits, encoded)
	sign := e.value("select i1 %s, i%d %d, i%d 0", negative, bits, uint64(1)<<(bits-1), bits)
	encoded = e.value("or i%d %s, %s", bits, encoded, sign)
	fmt.Fprintf(e.b, "  ret i%d %s\n}\n\n", bits, encoded)
}

func emitX86FloatMulDivUnboundedTiny(e *amd64FMA3IntegerEmitter, fractionBits, bias int, magnitude, shift, highest, unit, isNearest, awayFromZero string) string {
	// Here shift is highest-fractionBits, not the subnormal-grid shift.
	// Its domain is [-52, 53] for a product, or exactly 3 for a quotient.
	positive := e.value("icmp sgt i32 %s, 0", shift)
	rightCount := e.value("select i1 %s, i32 %s, i32 0", positive, shift)
	rightCount = e.value("zext i32 %s to i128", rightCount)
	right := e.value("lshr i128 %s, %s", magnitude, rightCount)
	leftCount := e.value("sub i32 0, %s", shift)
	leftCount = e.value("select i1 %s, i32 0, i32 %s", positive, leftCount)
	leftCount = e.value("zext i32 %s to i128", leftCount)
	left := e.value("shl i128 %s, %s", magnitude, leftCount)
	unrounded := e.value("select i1 %s, i128 %s, i128 %s", positive, right, left)
	mask := e.value("shl i128 1, %s", rightCount)
	mask = e.value("sub i128 %s, 1", mask)
	remainder := e.value("and i128 %s, %s", magnitude, mask)
	inexact := e.value("icmp ne i128 %s, 0", remainder)
	halfCount := e.value("sub i32 %s, 1", shift)
	halfCount = e.value("select i1 %s, i32 %s, i32 0", positive, halfCount)
	halfCount = e.value("zext i32 %s to i128", halfCount)
	half := e.value("shl i128 1, %s", halfCount)
	above := e.value("icmp ugt i128 %s, %s", remainder, half)
	tied := e.value("icmp eq i128 %s, %s", remainder, half)
	odd := e.value("and i128 %s, 1", unrounded)
	odd = e.value("icmp ne i128 %s, 0", odd)
	tied = e.value("and i1 %s, %s", tied, odd)
	nearest := e.value("or i1 %s, %s", above, tied)
	nearest = e.value("and i1 %s, %s", positive, nearest)
	directed := e.value("and i1 %s, %s", awayFromZero, inexact)
	increment := e.value("select i1 %s, i1 %s, i1 %s", isNearest, nearest, directed)
	increment = e.value("zext i1 %s to i128", increment)
	rounded := e.value("add i128 %s, %s", unrounded, increment)
	carry := e.value("icmp uge i128 %s, %d", rounded, uint64(1)<<(fractionBits+1))
	carry32 := e.value("zext i1 %s to i32", carry)
	top := e.value("add i32 %s, %s", highest, unit)
	top = e.value("add i32 %s, %s", top, carry32)
	return e.value("icmp slt i32 %s, %d", top, 1-bias)
}
