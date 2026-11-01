package plan9asm

import (
	"fmt"
	"math"
)

// The software FIST value path uses integer-indefinite for a masked invalid
// conversion, not saturation. LLVM fptosi instead produces poison for NaN or
// an out-of-range rounded value. Sanitize its actual input before converting,
// so correctness does not depend on discarding an intermediate poison value.
// This does not supply an ambient CW, exception/trap or extended-value role.
func (c *amd64Ctx) convertRoundedX87Integer(value string, bits int) string {
	typ := amd64IntegerTypeForBits(bits) // The typed W/L/V callers supply 16/32/64.
	bound := math.Ldexp(1, bits-1)
	lower, upper := c.newTmp(), c.newTmp()
	valid, safe := c.newTmp(), c.newTmp()
	integer, result := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp oge double %s, 0x%016X\n", lower, value, math.Float64bits(-bound))
	fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, 0x%016X\n", upper, value, math.Float64bits(bound))
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", valid, lower, upper)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %s, double 0.000000e+00\n", safe, valid, value)
	fmt.Fprintf(c.b, "  %%%s = fptosi double %%%s to %s\n", integer, safe, typ)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %%%s, %s %d\n", result, valid, typ, integer, typ, int64(-1)<<uint(bits-1))
	return "%" + result
}
