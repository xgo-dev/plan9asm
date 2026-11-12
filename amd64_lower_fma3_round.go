package plan9asm

import (
	"fmt"
	"strings"
)

// LLVM 22 can lower fixed-rounding constrained FMA to an ambient-rounding
// libcall. Accumulate the exact product and addend with guard/sticky bits
// instead. The product needs at most 106 bits; a 128-bit accumulator retains
// every cancellation bit and enough low bits for one final IEEE rounding.
type amd64FMA3IntegerEmitter struct {
	b    *strings.Builder
	next int
}

func (e *amd64FMA3IntegerEmitter) value(format string, args ...any) string {
	name := fmt.Sprintf("%%fma%d", e.next)
	e.next++
	fmt.Fprintf(e.b, "  %s = %s\n", name, fmt.Sprintf(format, args...))
	return name
}

type amd64FMA3IntegerInput struct {
	negative, magnitude, exponent, finite, floating string
}

func (e *amd64FMA3IntegerEmitter) input(bits int, value, daz string) amd64FMA3IntegerInput {
	fractionBits, bias := 23, 127
	if bits == 64 {
		fractionBits, bias = 52, 1023
	}
	fractionMask := uint64(1)<<fractionBits - 1
	exponentMask := 2*bias + 1
	raw := e.value("bitcast %s %s to i%d", amd64FMA3LLVMType(1, bits), value, bits)
	negative := e.value("icmp slt i%d %s, 0", bits, raw)
	fraction := e.value("and i%d %s, %d", bits, raw, fractionMask)
	shifted := e.value("lshr i%d %s, %d", bits, raw, fractionBits)
	exponent := e.value("and i%d %s, %d", bits, shifted, exponentMask)
	subnormal := e.value("icmp eq i%d %s, 0", bits, exponent)
	normalMantissa := e.value("or i%d %s, %d", bits, fraction, uint64(1)<<fractionBits)
	mantissa := e.value("select i1 %s, i%d %s, i%d %s", subnormal, bits, fraction, bits, normalMantissa)
	flush := e.value("and i1 %s, %s", subnormal, daz)
	signBits := e.value("and i%d %s, %d", bits, raw, uint64(1)<<(bits-1))
	flushedBits := e.value("select i1 %s, i%d %s, i%d %s", flush, bits, signBits, bits, raw)
	floating := e.value("bitcast i%d %s to %s", bits, flushedBits, amd64FMA3LLVMType(1, bits))
	mantissa = e.value("select i1 %s, i%d 0, i%d %s", flush, bits, bits, mantissa)
	magnitude := e.value("zext i%d %s to i128", bits, mantissa)
	effectiveExponent := e.value("select i1 %s, i%d 1, i%d %s", subnormal, bits, bits, exponent)
	if bits == 64 {
		effectiveExponent = e.value("trunc i64 %s to i32", effectiveExponent)
	}
	unit := e.value("sub i32 %s, %d", effectiveExponent, bias+fractionBits)
	finite := e.value("icmp ne i%d %s, %d", bits, exponent, exponentMask)
	return amd64FMA3IntegerInput{negative, magnitude, unit, finite, floating}
}

// Shift right with jamming, never a poison out-of-range shift. Lost bits are
// represented by bit zero. When loss occurs the other operand has at least
// 21 exact trailing bits, so cancellation cannot erase the sticky witness.
func (e *amd64FMA3IntegerEmitter) align(magnitude, exponent, unit string) string {
	delta := e.value("sub i32 %s, %s", exponent, unit)
	left := e.value("icmp sge i32 %s, 0", delta)
	leftCount := e.value("select i1 %s, i32 %s, i32 0", left, delta)
	leftFar := e.value("icmp ugt i32 %s, 127", leftCount)
	leftCount = e.value("select i1 %s, i32 127, i32 %s", leftFar, leftCount)
	leftCount = e.value("zext i32 %s to i128", leftCount)
	shiftedLeft := e.value("shl i128 %s, %s", magnitude, leftCount)
	rightCount := e.value("sub i32 0, %s", delta)
	rightCount = e.value("select i1 %s, i32 0, i32 %s", left, rightCount)
	tooFar := e.value("icmp uge i32 %s, 128", rightCount)
	safe := e.value("select i1 %s, i32 127, i32 %s", tooFar, rightCount)
	safe = e.value("zext i32 %s to i128", safe)
	shiftedRight := e.value("lshr i128 %s, %s", magnitude, safe)
	shiftedRight = e.value("select i1 %s, i128 0, i128 %s", tooFar, shiftedRight)
	mask := e.value("shl i128 1, %s", safe)
	mask = e.value("sub i128 %s, 1", mask)
	lost := e.value("and i128 %s, %s", magnitude, mask)
	lost = e.value("select i1 %s, i128 %s, i128 %s", tooFar, magnitude, lost)
	sticky := e.value("icmp ne i128 %s, 0", lost)
	sticky = e.value("zext i1 %s to i128", sticky)
	jammed := e.value("or i128 %s, %s", shiftedRight, sticky)
	return e.value("select i1 %s, i128 %s, i128 %s", left, shiftedLeft, jammed)
}

func emitAMD64FMA3RoundingHelpers(b *strings.Builder, file *File, goarch string) {
	needed := make(map[int]bool)
	addSubNeeded := make(map[int]bool)
	addSubSpecial := make(map[int]bool)
	mulDivNeeded := make(map[int]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if form, known, err := x86FloatingHelperProperties(ins, goarch); known && err == nil {
				base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
				if spec, scaled := amd64ScaledRoundSpecs[Op(base)]; scaled && spec.mode == amd64Reduce {
					needed[form.spec.bits], addSubNeeded[form.spec.bits] = true, true
				}
			}
			if form, known, err := x86FloatMulDivProperties(ins, goarch); known && err == nil && form.rounding != "" {
				mulDivNeeded[form.bits] = true
			}
			if form, known, err := x86FloatAddSubProperties(ins, goarch); known && err == nil {
				addSubSpecial[form.spec.bits] = true
				if form.rounding != "" {
					needed[form.spec.bits], addSubNeeded[form.spec.bits] = true, true
				}
			}
			form, known, err := amd64FMA3Properties(ins, goarch)
			if known && err == nil && form.suffix.rounding != "" && !form.spec.rawOnly {
				needed[form.spec.laneBits] = true
			}
		}
	}
	if len(needed) == 0 && len(addSubSpecial) == 0 && len(mulDivNeeded) == 0 {
		return
	}
	if len(needed) > 0 || len(mulDivNeeded) > 0 {
		b.WriteString("declare i128 @llvm.ctlz.i128(i128, i1)\n")
	}
	for _, bits := range []int{32, 64} {
		if mulDivNeeded[bits] {
			emitX86FloatMulDivRoundingHelper(b, bits)
		}
		if addSubSpecial[bits] {
			emitX86FloatAddSubSpecialHelper(b, bits)
		}
		if needed[bits] {
			emitAMD64FMA3RoundingHelper(b, bits)
			if addSubNeeded[bits] {
				emitX86FloatAddSubRoundingHelper(b, bits)
			}
		}
	}
}

func emitAMD64FMA3RoundingHelper(b *strings.Builder, bits int) {
	fractionBits, bias := 23, 127
	if bits == 64 {
		fractionBits, bias = 52, 1023
	}
	floatType := amd64FMA3LLVMType(1, bits)
	name := fmt.Sprintf("__plan9asm_fma3_round_f%d", bits)
	fmt.Fprintf(b, "define internal %s @%s(%s %%a, %s %%b, %s %%c, i32 %%mode, i32 %%mxcsr) {\nentry:\n", floatType, name, floatType, floatType, floatType)
	e := amd64FMA3IntegerEmitter{b: b}
	daz := e.value("and i32 %%mxcsr, 64")
	daz = e.value("icmp ne i32 %s, 0", daz)
	a, multiplier, addend := e.input(bits, "%a", daz), e.input(bits, "%b", daz), e.input(bits, "%c", daz)
	finite := e.value("and i1 %s, %s", a.finite, multiplier.finite)
	finite = e.value("and i1 %s, %s", finite, addend.finite)
	fmt.Fprintf(b, "  br i1 %s, label %%finite, label %%special\nspecial:\n", finite)
	// Preserve the existing target's NaN/infinity behavior without executing
	// a floating operation on the finite software path or changing host fenv.
	fmt.Fprintf(b, "  %%special_result = call %s @llvm.fma.f%d(%s %s, %s %s, %s %s)\n  ret %s %%special_result\nfinite:\n", floatType, bits, floatType, a.floating, floatType, multiplier.floating, floatType, addend.floating, floatType)
	product := e.value("mul i128 %s, %s", a.magnitude, multiplier.magnitude)
	productExponent := e.value("add i32 %s, %s", a.exponent, multiplier.exponent)
	productSign := e.value("xor i1 %s, %s", a.negative, multiplier.negative)
	productTop := e.value("add i32 %s, %d", productExponent, 2*fractionBits+1)
	addendTop := e.value("add i32 %s, %d", addend.exponent, fractionBits)
	largerTop := e.value("icmp sgt i32 %s, %s", productTop, addendTop)
	top := e.value("select i1 %s, i32 %s, i32 %s", largerTop, productTop, addendTop)
	// A zero contribution has no exponent. In particular, a huge operand
	// multiplied by zero must not erase a tiny nonzero addend into sticky.
	originalTop := top
	productZero := e.value("icmp eq i128 %s, 0", product)
	addendZero := e.value("icmp eq i128 %s, 0", addend.magnitude)
	top = e.value("select i1 %s, i32 %s, i32 %s", productZero, addendTop, top)
	top = e.value("select i1 %s, i32 %s, i32 %s", addendZero, productTop, top)
	bothZero := e.value("and i1 %s, %s", productZero, addendZero)
	top = e.value("select i1 %s, i32 %s, i32 %s", bothZero, originalTop, top)
	unit := e.value("sub i32 %s, 126", top)
	product = e.align(product, productExponent, unit)
	add := e.align(addend.magnitude, addend.exponent, unit)
	sameSign := e.value("icmp eq i1 %s, %s", productSign, addend.negative)
	productLarger := e.value("icmp uge i128 %s, %s", product, add)
	sum := e.value("add i128 %s, %s", product, add)
	difference := e.value("sub i128 %s, %s", product, add)
	reverseDifference := e.value("sub i128 %s, %s", add, product)
	difference = e.value("select i1 %s, i128 %s, i128 %s", productLarger, difference, reverseDifference)
	magnitude := e.value("select i1 %s, i128 %s, i128 %s", sameSign, sum, difference)
	negative := e.value("select i1 %s, i1 %s, i1 %s", productLarger, productSign, addend.negative)
	zero := e.value("icmp eq i128 %s, 0", magnitude)
	downward := e.value("icmp eq i32 %%mode, 1")
	zeroSign := e.value("select i1 %s, i1 %s, i1 %s", sameSign, productSign, downward)
	negative = e.value("select i1 %s, i1 %s, i1 %s", zero, zeroSign, negative)
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
	flush := e.value("and i1 %s, %s", ftz, stillSubnormal)
	encoded = e.value("select i1 %s, i%d 0, i%d %s", flush, bits, bits, encoded)
	sign := e.value("select i1 %s, i%d %d, i%d 0", negative, bits, uint64(1)<<(bits-1), bits)
	encoded = e.value("or i%d %s, %s", bits, encoded, sign)
	result := e.value("bitcast i%d %s to %s", bits, encoded, floatType)
	fmt.Fprintf(b, "  ret %s %s\n}\n\n", floatType, result)
}

func (c *amd64Ctx) emitRoundedFMA3(lanes, bits int, a, b, addend, rounding string) string {
	floatType := amd64FMA3LLVMType(1, bits)
	vectorType := amd64FMA3LLVMType(lanes, bits)
	mode := c.packedNumericRoundingMode(rounding)
	mxcsr := c.loadMXCSR()
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		values := []string{a, b, addend}
		if lanes > 1 {
			for index, value := range values {
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, vectorType, value, lane)
				values[index] = "%" + extracted
			}
		}
		computed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @__plan9asm_fma3_round_f%d(%s %s, %s %s, %s %s, i32 %s, i32 %s)\n", computed, floatType, bits, floatType, values[0], floatType, values[1], floatType, values[2], mode, mxcsr)
		if lanes == 1 {
			return "%" + computed
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, vectorType, result, floatType, computed, lane)
		result = "%" + inserted
	}
	return result
}
