package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

func emitWASMV128UnsignedAverage(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, result, lhs, rhs string) {
	// (a | b) - ((a ^ b) >> 1) rounds up without overflowing the lane.
	different, either, half := newTmp(), newTmp(), newTmp()
	typ := shape.LaneType
	fmt.Fprintf(b, "  %%%s = xor %s %s, %s\n", different, typ, lhs, rhs)
	fmt.Fprintf(b, "  %%%s = or %s %s, %s\n", either, typ, lhs, rhs)
	fmt.Fprintf(b, "  %%%s = lshr %s %%%s, %s\n", half, typ, different, wasmV128IntegerLiteral(128/shape.LaneBits, shape.LaneBits, 1))
	fmt.Fprintf(b, "  %%%s = sub %s %%%s, %%%s\n", result, typ, either, half)
}

func emitWASMV128Q15(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, result, lhs, rhs string) {
	lanes := 128 / shape.LaneBits
	wide := fmt.Sprintf("<%d x i32>", lanes)
	limit := wasmV128IntegerLiteral(lanes, 32, 32767)
	left, right, product := newTmp(), newTmp(), newTmp()
	rounded, scaled, overflow, clamped := newTmp(), newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = sext %s %s to %s\n", left, shape.LaneType, lhs, wide)
	fmt.Fprintf(b, "  %%%s = sext %s %s to %s\n", right, shape.LaneType, rhs, wide)
	fmt.Fprintf(b, "  %%%s = mul %s %%%s, %%%s\n", product, wide, left, right)
	fmt.Fprintf(b, "  %%%s = add %s %%%s, %s\n", rounded, wide, product, wasmV128IntegerLiteral(lanes, 32, 16384))
	fmt.Fprintf(b, "  %%%s = ashr %s %%%s, %s\n", scaled, wide, rounded, wasmV128IntegerLiteral(lanes, 32, 15))
	// The minimum-times-minimum product is the only out-of-range result.
	// The deterministic relaxed form saturates it like the ordinary form.
	fmt.Fprintf(b, "  %%%s = icmp sgt %s %%%s, %s\n", overflow, wide, scaled, limit)
	fmt.Fprintf(b, "  %%%s = select %s %%%s, %s %s, %s %%%s\n", clamped, shape.PredicateType, overflow, wide, limit, wide, scaled)
	fmt.Fprintf(b, "  %%%s = trunc %s %%%s to %s\n", result, wide, clamped, shape.LaneType)
}

func emitWASMV128IntegerDot(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, lhs, rhs string) string {
	pair := spec.DotPairShape()
	source := spec.InputLaneType()
	multiply := func(offset int) string {
		left := emitWASMV128WidenedLanes(b, newTmp, source, lhs, pair, offset, 2, "sext")
		right := emitWASMV128WidenedLanes(b, newTmp, source, rhs, pair, offset, 2, "sext")
		product := newTmp()
		fmt.Fprintf(b, "  %%%s = mul %s %s, %s\n", product, pair.LaneType, left, right)
		return "%" + product
	}
	even, odd, sum := multiply(0), multiply(1), newTmp()
	fmt.Fprintf(b, "  %%%s = add %s %s, %s\n", sum, pair.LaneType, even, odd)
	value := "%" + sum
	if spec.Arity() == 3 {
		// Wrap the signed i16 pairs before widening into the i32 accumulator.
		value = emitWASMV128WidenedPairSum(b, newTmp, pair.LaneType, value, spec.Shape, "sext")
	}
	return value
}

func emitWASMV128WidenedPairSum(b *strings.Builder, newTmp func() string, source, input string, shape wasmsimd.Shape, extension string) string {
	left := emitWASMV128WidenedLanes(b, newTmp, source, input, shape, 0, 2, extension)
	right := emitWASMV128WidenedLanes(b, newTmp, source, input, shape, 1, 2, extension)
	sum := newTmp()
	fmt.Fprintf(b, "  %%%s = add %s %s, %s\n", sum, shape.LaneType, left, right)
	return "%" + sum
}

func emitWASMV128WidenedLanes(b *strings.Builder, newTmp func() string, source, input string, shape wasmsimd.Shape, first, step int, extension string) string {
	lanes := 128 / shape.LaneBits
	half := fmt.Sprintf("<%d x i%d>", lanes, shape.LaneBits/2)
	picked, extended := newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
		picked, source, input, source, lanes, wasmV128ShuffleIndices(lanes, first, step))
	fmt.Fprintf(b, "  %%%s = %s %s %%%s to %s\n", extended, extension, half, picked, shape.LaneType)
	return "%" + extended
}
