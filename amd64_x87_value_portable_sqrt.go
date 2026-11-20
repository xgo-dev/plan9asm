package plan9asm

import "fmt"

// FSQRT consumes the same complete value and explicit control word as the
// other portable providers. This helper returns value bits, not status flags,
// source authority, or a statement about an ambient hardware control word.
func (c *amd64Ctx) x87PortableSquareRoot(value x87Value, cw string) (x87Value, error) {
	input := c.x87PortableDecode(value)
	leading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", input.significand)
	shift := c.x87PortableIR("and i64 %s, 63", leading)
	normalized := c.x87PortableIR("shl i64 %s, %s", input.significand, shift)
	leading32 := c.x87PortableIR("trunc i64 %s to i32", leading)
	highest := c.x87PortableIR("add i32 %s, 63", input.unit)
	highest = c.x87PortableIR("sub i32 %s, %s", highest, leading32)
	rootExponent := c.x87PortableIR("ashr i32 %s, 1", highest)
	unit := c.x87PortableIR("sub i32 %s, 66", rootExponent)
	parity := c.x87PortableIR("and i32 %s, 1", highest)
	odd := c.x87PortableIR("icmp ne i32 %s, 0", parity)
	wide := c.x87PortableIR("zext i64 %s to i128", normalized)
	evenStream := c.x87PortableIR("shl i128 %s, 63", wide)
	oddStream := c.x87PortableIR("shl i128 %s, 64", wide)
	initial := c.x87PortableIR("select i1 %s, i128 %s, i128 %s", odd, oddStream, evenStream)

	// The full radicand has 133/134 bits. Its last six bits are zero, so
	// streaming 128 bits and then three zero pairs avoids truncating it into
	// an i128. Restoring base-four extraction needs only a 67-bit root and
	// a remainder smaller than twice the root plus one.
	identifier := c.newTmp()
	prepare := "x87_sqrt_prepare_" + identifier
	loop := "x87_sqrt_loop_" + identifier
	done := "x87_sqrt_done_" + identifier
	stream, root, remainder, iteration := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	nextStream, nextRoot, nextRemainder, nextIteration := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  br label %%%s\n%s:\n  br label %%%s\n%s:\n", prepare, prepare, loop, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i128 [ %s, %%%s ], [ %%%s, %%%s ]\n", stream, initial, prepare, nextStream, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i128 [ 0, %%%s ], [ %%%s, %%%s ]\n", root, prepare, nextRoot, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i128 [ 0, %%%s ], [ %%%s, %%%s ]\n", remainder, prepare, nextRemainder, loop)
	fmt.Fprintf(c.b, "  %%%s = phi i32 [ 0, %%%s ], [ %%%s, %%%s ]\n", iteration, prepare, nextIteration, loop)
	pair := c.x87PortableIR("lshr i128 %%%s, 126", stream)
	expanded := c.x87PortableIR("shl i128 %%%s, 2", remainder)
	expanded = c.x87PortableIR("or i128 %s, %s", expanded, pair)
	trial := c.x87PortableIR("shl i128 %%%s, 2", root)
	trial = c.x87PortableIR("or i128 %s, 1", trial)
	bit := c.x87PortableIR("icmp uge i128 %s, %s", expanded, trial)
	difference := c.x87PortableIR("sub i128 %s, %s", expanded, trial)
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i128 %s, i128 %s\n", nextRemainder, bit, difference, expanded)
	doubledRoot := c.x87PortableIR("shl i128 %%%s, 1", root)
	bit128 := c.x87PortableIR("zext i1 %s to i128", bit)
	fmt.Fprintf(c.b, "  %%%s = or i128 %s, %s\n", nextRoot, doubledRoot, bit128)
	fmt.Fprintf(c.b, "  %%%s = shl i128 %%%s, 2\n", nextStream, stream)
	fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, 1\n", nextIteration, iteration)
	finished := c.x87PortableIR("icmp eq i32 %%%s, 67", nextIteration)
	fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n%s:\n", finished, done, loop, done)
	sticky := c.x87PortableIR("icmp ne i128 %%%s, 0", nextRemainder)
	sticky = c.x87PortableIR("zext i1 %s to i128", sticky)
	magnitude := c.x87PortableIR("or i128 %%%s, %s", nextRoot, sticky)
	result := c.x87PortableRoundPack(magnitude, unit, "false", cw)

	result = c.x87PortableChoose(input.zero, value, result)
	result = c.x87PortableChoose(input.infinite, value, result)
	nonzero := c.x87PortableIR("xor i1 %s, true", input.zero)
	negativeNonzero := c.x87PortableIR("and i1 %s, %s", input.negative, nonzero)
	indefinite := c.packX87("13835058055282163712", "65535")
	result = c.x87PortableChoose(negativeNonzero, indefinite, result)
	invalid := c.x87PortableIR("or i1 %s, %s", input.nan, input.unsupported)
	return c.x87PortableChoose(invalid, c.x87PortableQuietNaN(input), result), nil
}
