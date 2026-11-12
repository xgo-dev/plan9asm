package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ApproximateMathMode uint8

const (
	amd64ApproximateExp2 amd64ApproximateMathMode = iota
	amd64ApproximateReciprocal28
	amd64ApproximateReciprocalSqrt28
)

type amd64ApproximateMathSpec struct {
	laneBits int
	scalar   bool
	mode     amd64ApproximateMathMode
}

// amd64ApproximateMathSpecs models the complete AVX512ER family exposed by
// Go 1.27's _yvexp2pd and _yvgetexpsd tables. The type axes describe the
// mathematical operation, lane type, and packed/scalar operand shape; the
// parser below derives every legal mask, zero, broadcast, and SAE form.
var amd64ApproximateMathSpecs = map[Op]amd64ApproximateMathSpec{
	"VEXP2PS":    {laneBits: 32, mode: amd64ApproximateExp2},
	"VEXP2PD":    {laneBits: 64, mode: amd64ApproximateExp2},
	"VRCP28PS":   {laneBits: 32, mode: amd64ApproximateReciprocal28},
	"VRCP28PD":   {laneBits: 64, mode: amd64ApproximateReciprocal28},
	"VRCP28SS":   {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRCP28SD":   {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRSQRT28PS": {laneBits: 32, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28PD": {laneBits: 64, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SS": {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SD": {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
}

// All ten EVEX approximation members share the existing typed native helper.
// The original instruction owns SAE/MXCSR, masking and the actual memory access;
// source data is never eagerly loaded before a masked native instruction.
func (c *amd64Ctx) lowerApproximateMath(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64ApproximateMathSpecs[Op(base)]; !known {
		return false, false, nil
	}
	return c.lowerNativeFloatingHelper(op, ins)
}

func (c *amd64Ctx) approximateMathMask32(mask string) string {
	truncated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, mask)
	return "%" + truncated
}
