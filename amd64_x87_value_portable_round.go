package plan9asm

import "fmt"

// FRNDINT rounds the full significand onto an integer grid; PC does not
// shorten that result. Large integers and signed zeros never pass through an
// I64 conversion or a binary64 intermediary. All shifts remain bounded even
// in branches whose result will be discarded for an infinity or NaN.
func (c *amd64Ctx) x87PortableRound(value x87Value, cw string) (x87Value, error) {
	significand, signExponent := c.partsX87(value)
	exponent16 := c.x87PortableIR("and i16 %s, 32767", signExponent)
	exponent := c.x87PortableIR("zext i16 %s to i32", exponent16)
	zeroExponent := c.x87PortableIR("icmp eq i32 %s, 0", exponent)
	effectiveExponent := c.x87PortableIR("select i1 %s, i32 1, i32 %s", zeroExponent, exponent)
	shift := c.x87PortableIR("sub i32 16446, %s", effectiveExponent)
	negative := c.x87PortableIR("icmp slt i16 %s, 0", signExponent)
	magnitude := c.x87PortableRoundedShift(significand, shift, negative, cw)
	leading := c.x87PortableIR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", magnitude)
	safeLeading := c.x87PortableIR("and i64 %s, 63", leading)
	roundedSignificand := c.x87PortableIR("shl i64 %s, %s", magnitude, safeLeading)
	roundedExponent := c.x87PortableIR("sub i64 16446, %s", leading)
	zero := c.x87PortableIR("icmp eq i64 %s, 0", magnitude)
	roundedExponent = c.x87PortableIR("select i1 %s, i64 0, i64 %s", zero, roundedExponent)
	roundedExponent = c.x87PortableIR("trunc i64 %s to i16", roundedExponent)
	sign := c.x87PortableIR("and i16 %s, 32768", signExponent)
	roundedExponent = c.x87PortableIR("or i16 %s, %s", roundedExponent, sign)
	rounded := c.packX87(roundedSignificand, roundedExponent)
	integer := c.x87PortableIR("icmp uge i32 %s, 16446", exponent)
	selected := c.x87PortableIR("select i1 %s, %s %s, %s %s", integer, x87ValueType, value, x87ValueType, rounded)

	special := c.x87PortableIR("icmp eq i32 %s, 32767", exponent)
	payload := c.x87PortableIR("and i64 %s, 9223372036854775807", significand)
	nonzeroPayload := c.x87PortableIR("icmp ne i64 %s, 0", payload)
	nan := c.x87PortableIR("and i1 %s, %s", special, nonzeroPayload)
	quiet := c.x87PortableIR("or i64 %s, 4611686018427387904", significand)
	quietValue := c.packX87(quiet, signExponent)
	selected = c.x87PortableIR("select i1 %s, %s %s, %s %s", nan, x87ValueType, quietValue, x87ValueType, selected)
	missingInteger := c.x87PortableIR("icmp sge i64 %s, 0", significand)
	nonzeroExponent := c.x87PortableIR("xor i1 %s, true", zeroExponent)
	unsupported := c.x87PortableIR("and i1 %s, %s", missingInteger, nonzeroExponent)
	indefinite := c.packX87("13835058055282163712", "65535")
	return x87Value(c.x87PortableIR("select i1 %s, %s %s, %s %s", unsupported, x87ValueType, indefinite, x87ValueType, selected)), nil
}

func (c *amd64Ctx) x87PortableUnary(op Op, value x87Value, cw string) (x87Value, error) {
	if op == "FSQRT" {
		return c.x87PortableSquareRoot(value, cw)
	}
	if op == "FRNDINT" {
		return c.x87PortableRound(value, cw)
	}
	if op != "FABS" && op != "FCHS" {
		return "", fmt.Errorf("unsupported portable x87 unary operation %s", op)
	}
	significand, signExponent := c.partsX87(value)
	if op == "FABS" {
		signExponent = c.x87PortableIR("and i16 %s, 32767", signExponent)
	} else {
		signExponent = c.x87PortableIR("xor i16 %s, 32768", signExponent)
	}
	return c.packX87(significand, signExponent), nil
}
