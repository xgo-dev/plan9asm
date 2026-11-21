package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

// All SIMD lane formats share the same 128-bit register and stack carrier.
const wasmV128CoreType = LLVMType(wasmsimd.V128)

func parseWASMV128Core(ins Instr, name string) (wasmsimd.Form, bool, error) {
	spec, found := wasmsimd.Lookup(name)
	if !found {
		return spec, false, nil
	}
	operands := 0
	if spec.Operator == "const" {
		operands = 2
	}
	if strings.ToUpper(string(ins.Op)) != name || len(ins.Args) != operands {
		return spec, true, fmt.Errorf("%s requires %d operands and no suffix: %q", name, operands, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" {
			return spec, true, fmt.Errorf("%s requires two resolved 64-bit integer literals: %q", name, ins.Raw)
		}
	}
	return spec, true, nil
}

// Values arrive in Wasm source order, not pop order: Bitselect's third input
// is the mask, and Andnot complements only the second input.
func emitWASMV128Core(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, ins Instr, inputs []wasmValue) wasmValue {
	if spec.Emission != wasmsimd.Core {
		return emitWASMV128Lanes(b, newTmp, spec, inputs)
	}
	if spec.Operator == "const" {
		low, high := uint64(ins.Args[0].Imm), uint64(ins.Args[1].Imm)
		value := fmt.Sprintf("<i32 %d, i32 %d, i32 %d, i32 %d>",
			int32(low), int32(low>>32), int32(high), int32(high>>32))
		return wasmValue{typ: wasmV128CoreType, val: value}
	}
	binary := func(operation, a, c string) string {
		result := newTmp()
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", result, operation, wasmV128CoreType, a, c)
		return "%" + result
	}
	invert := func(value string) string {
		return binary("xor", value, "<i32 -1, i32 -1, i32 -1, i32 -1>")
	}
	var result string
	switch spec.Operator {
	case "not":
		result = invert(inputs[0].val)
	case "andnot":
		result = binary("and", inputs[0].val, invert(inputs[1].val))
	case "bitselect":
		mask := inputs[2].val
		first := binary("and", inputs[0].val, mask)
		second := binary("and", inputs[1].val, invert(mask))
		result = binary("or", first, second)
	case "anytrue":
		bits, nonzero, integer := newTmp(), newTmp(), newTmp()
		fmt.Fprintf(b, "  %%%s = bitcast %s %s to i128\n", bits, wasmV128CoreType, inputs[0].val)
		fmt.Fprintf(b, "  %%%s = icmp ne i128 %%%s, 0\n", nonzero, bits)
		fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", integer, nonzero)
		result = "%" + integer
	default: // The descriptor's remaining three operations are LLVM bitwise ops.
		result = binary(spec.Operator, inputs[0].val, inputs[1].val)
	}
	return wasmValue{typ: LLVMType(spec.ResultType()), val: result}
}

func emitWASMV128Lanes(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, inputs []wasmValue) wasmValue {
	typ := spec.Shape.LaneType
	cast := func(value string, from, to LLVMType) string {
		if from == to {
			return value
		}
		result := newTmp()
		fmt.Fprintf(b, "  %%%s = bitcast %s %s to %s\n", result, from, value, to)
		return "%" + result
	}

	lhs := cast(inputs[0].val, wasmV128CoreType, LLVMType(typ))
	var rhs string
	if len(inputs) == 2 && spec.InputType(1) == wasmsimd.V128 {
		rhs = cast(inputs[1].val, wasmV128CoreType, LLVMType(typ))
	}
	resultType := LLVMType(typ)
	result := newTmp()
	switch spec.Emission {
	case wasmsimd.Instruction:
		fmt.Fprintf(b, "  %%%s = %s %s %s", result, spec.Operator, typ, lhs)
		if rhs != "" {
			fmt.Fprintf(b, ", %s", rhs)
		}
		b.WriteByte('\n')
	case wasmsimd.Intrinsic:
		fmt.Fprintf(b, "  %%%s = call %s @%s(%s %s", result, typ, spec.IntrinsicName(), typ, lhs)
		if rhs != "" {
			fmt.Fprintf(b, ", %s %s", typ, rhs)
		}
		b.WriteString(")\n")
	case wasmsimd.IntegerAbs:
		// The minimum signed lane wraps to itself.
		fmt.Fprintf(b, "  %%%s = call %s @%s(%s %s, i1 false)\n", result, typ, spec.IntrinsicName(), typ, lhs)
	case wasmsimd.IntegerNeg:
		fmt.Fprintf(b, "  %%%s = sub %s zeroinitializer, %s\n", result, typ, lhs)
	case wasmsimd.Shift:
		amount := emitWASMV128ShiftCount(b, newTmp, spec.Shape, inputs[1].val)
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", result, spec.Operator, typ, lhs, amount)
	case wasmsimd.AllTrue, wasmsimd.Bitmask:
		return emitWASMV128Reduction(b, newTmp, spec, lhs)
	case wasmsimd.Compare, wasmsimd.FloatSelect:
		predicate := newTmp()
		fmt.Fprintf(b, "  %%%s = %s %s %s %s, %s\n", predicate, spec.Shape.Comparator, spec.Operator, typ, lhs, rhs)
		if spec.Emission == wasmsimd.Compare {
			// Wasm's true lanes contain all one bits.
			resultType = LLVMType(spec.Shape.MaskType)
			fmt.Fprintf(b, "  %%%s = sext %s %%%s to %s\n", result, spec.Shape.PredicateType, predicate, resultType)
		} else {
			// Pseudo-min/max choose the first operand on a tie or an unordered comparison.
			fmt.Fprintf(b, "  %%%s = select %s %%%s, %s %s, %s %s\n", result, spec.Shape.PredicateType, predicate, typ, rhs, typ, lhs)
		}
	}
	value := "%" + result
	if spec.CanonicalNaN {
		integerType := LLVMType(spec.Shape.MaskType)
		value = emitWASMV128CanonicalNaN(b, newTmp, spec.Shape, cast(value, resultType, integerType))
		resultType = integerType
	}
	return wasmValue{typ: wasmV128CoreType, val: cast(value, resultType, wasmV128CoreType)}
}

func emitWASMV128CanonicalNaN(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, value string) string {
	// LLVM can fold arithmetic to an operand when the operand is aliased or
	// another input is an identity. Check the lane bits after the operation
	// so a dynamic signaling NaN still becomes a valid Wasm arithmetic NaN.
	bits := shape.LaneBits
	signless, infinity, canonical := wasmFloatNaNBits(bits)
	splat := func(bitsValue uint64) string {
		lane := fmt.Sprintf("i%d %d", bits, bitsValue)
		return "<" + strings.Repeat(lane+", ", 128/bits-1) + lane + ">"
	}
	typ := shape.MaskType
	magnitude, isNaN, result := newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = and %s %s, %s\n", magnitude, typ, value, splat(signless))
	fmt.Fprintf(b, "  %%%s = icmp ugt %s %%%s, %s\n", isNaN, typ, magnitude, splat(infinity))
	fmt.Fprintf(b, "  %%%s = select %s %%%s, %s %s, %s %s\n",
		result, shape.PredicateType, isNaN, typ, splat(canonical), typ, value)
	return "%" + result
}

func emitWASMV128ShiftCount(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, count string) string {
	bits := shape.LaneBits
	// LLVM shifts require bounded counts. Wasm takes the count modulo the
	// lane width before applying it to each lane.
	masked := newTmp()
	fmt.Fprintf(b, "  %%%s = and i32 %s, %d\n", masked, count, bits-1)
	count = "%" + masked
	if bits != 32 {
		operation := "trunc"
		if bits > 32 {
			operation = "zext"
		}
		converted := newTmp()
		fmt.Fprintf(b, "  %%%s = %s i32 %s to i%d\n", converted, operation, count, bits)
		count = "%" + converted
	}
	seed, splat := newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = insertelement %s poison, i%d %s, i32 0\n", seed, shape.LaneType, bits, count)
	fmt.Fprintf(b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n",
		splat, shape.LaneType, seed, shape.LaneType, 128/bits)
	return "%" + splat
}

func emitWASMV128Reduction(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, input string) wasmValue {
	lanes := 128 / spec.Shape.LaneBits
	predicate, bits, result := newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = icmp %s %s %s, zeroinitializer\n", predicate, spec.Operator, spec.Shape.LaneType, input)
	fmt.Fprintf(b, "  %%%s = bitcast %s %%%s to i%d\n", bits, spec.Shape.PredicateType, predicate, lanes)
	if spec.Emission == wasmsimd.AllTrue {
		all := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp eq i%d %%%s, -1\n", all, lanes, bits)
		fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", result, all)
	} else {
		// The target's little-endian vector layout puts lane zero in bit zero.
		fmt.Fprintf(b, "  %%%s = zext i%d %%%s to i32\n", result, lanes, bits)
	}
	return wasmValue{typ: LLVMType(spec.ResultType()), val: "%" + result}
}
