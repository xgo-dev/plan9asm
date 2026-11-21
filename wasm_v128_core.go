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
	switch {
	case spec.HasLaneIndex():
		// Go writes the selector from the destination operand. Its unary
		// syntax leaves that field zero, regardless of the written literal.
		operands = 2
	case spec.Operator == "const", spec.Emission == wasmsimd.ByteShuffle:
		operands = 2
	}
	if strings.ToUpper(string(ins.Op)) != name || len(ins.Args) != operands {
		return spec, true, fmt.Errorf("%s requires %d operands and no suffix: %q", name, operands, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpImm || operand.ImmIsFloat || operand.ImmRaw != "" {
			return spec, true, fmt.Errorf("%s requires resolved integer literals: %q", name, ins.Raw)
		}
		// Like V128Const, Shuffle16 packs its bytes into two little-endian
		// 64-bit immediates. Each selector names one byte of two 16-byte inputs.
		if spec.Emission == wasmsimd.ByteShuffle && uint64(operand.Imm)&0xe0e0e0e0e0e0e0e0 != 0 {
			return spec, true, fmt.Errorf("%s requires 16 packed byte selectors in 0..31: %q", name, ins.Raw)
		}
	}
	if spec.HasLaneIndex() {
		lane := ins.Args[1].Imm
		lanes := int64(128 / spec.Shape.LaneBits)
		if lane < 0 || lane >= lanes {
			return spec, true, fmt.Errorf("%s lane index %d outside 0..%d: %q", name, lane, lanes-1, ins.Raw)
		}
	}
	return spec, true, nil
}

// Values arrive in Wasm source order, not pop order: Bitselect's third input
// is the mask, and Andnot complements only the second input.
func emitWASMV128Core(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, ins Instr, inputs []wasmValue) wasmValue {
	if spec.Emission != wasmsimd.Core {
		return emitWASMV128Lanes(b, newTmp, spec, ins, inputs)
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

func emitWASMVectorBitcast(b *strings.Builder, newTmp func() string, value string, from, to LLVMType) string {
	if from == to {
		return value
	}
	result := newTmp()
	fmt.Fprintf(b, "  %%%s = bitcast %s %s to %s\n", result, from, value, to)
	return "%" + result
}

func emitWASMV128Lanes(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, ins Instr, inputs []wasmValue) wasmValue {
	typ := spec.Shape.LaneType
	inputType := LLVMType(spec.InputLaneType())
	cast := func(value string, from, to LLVMType) string {
		return emitWASMVectorBitcast(b, newTmp, value, from, to)
	}

	lhs := inputs[0].val
	if spec.InputType(0) == wasmsimd.V128 {
		lhs = cast(lhs, wasmV128CoreType, inputType)
	}
	var rhs string
	if len(inputs) >= 2 && spec.InputType(1) == wasmsimd.V128 {
		rhs = cast(inputs[1].val, wasmV128CoreType, inputType)
	}
	resultType := LLVMType(typ)
	result := newTmp()
	switch spec.Emission {
	case wasmsimd.ByteShuffle:
		var mask strings.Builder
		for lane := 0; lane < 16; lane++ {
			if lane != 0 {
				mask.WriteString(", ")
			}
			index := byte(uint64(ins.Args[lane/8].Imm) >> (8 * (lane % 8)))
			fmt.Fprintf(&mask, "i32 %d", index)
		}
		fmt.Fprintf(b, "  %%%s = shufflevector %s %s, %s %s, <16 x i32> <%s>\n",
			result, typ, lhs, typ, rhs, mask.String())
	case wasmsimd.ByteSwizzle:
		result = emitWASMByteSwizzle(b, newTmp, typ, lhs, rhs)
	case wasmsimd.FloatMultiplyAdd:
		third := cast(inputs[2].val, wasmV128CoreType, inputType)
		if spec.Operator == "fneg" {
			negated := newTmp()
			fmt.Fprintf(b, "  %%%s = fneg %s %s\n", negated, typ, lhs)
			lhs = "%" + negated
		}
		// The deterministic profile rounds the product before the sum.
		// Keep both operations free of LLVM's contract/fast math flags.
		product := newTmp()
		fmt.Fprintf(b, "  %%%s = fmul %s %s, %s\n", product, typ, lhs, rhs)
		fmt.Fprintf(b, "  %%%s = fadd %s %%%s, %s\n", result, typ, product, third)
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
	case wasmsimd.IntegerAverage:
		emitWASMV128UnsignedAverage(b, newTmp, spec.Shape, result, lhs, rhs)
	case wasmsimd.IntegerQ15:
		emitWASMV128Q15(b, newTmp, spec.Shape, result, lhs, rhs)
	case wasmsimd.IntegerDot:
		dot := emitWASMV128IntegerDot(b, newTmp, spec, lhs, rhs)
		if spec.Arity() == 3 {
			fmt.Fprintf(b, "  %%%s = add %s %s, %s\n", result, typ, dot, inputs[2].val)
		} else {
			return wasmValue{typ: wasmV128CoreType, val: cast(dot, resultType, wasmV128CoreType)}
		}
	case wasmsimd.IntegerWiden:
		wide := emitWASMV128IntegerWiden(b, newTmp, spec, lhs, rhs)
		return wasmValue{typ: wasmV128CoreType, val: cast(wide, resultType, wasmV128CoreType)}
	case wasmsimd.IntegerNarrow:
		emitWASMV128IntegerNarrow(b, newTmp, spec, result, lhs, rhs)
	case wasmsimd.Convert:
		result = emitWASMV128Conversion(b, newTmp, spec, result, lhs)
	case wasmsimd.Shift:
		amount := emitWASMV128ShiftCount(b, newTmp, spec.Shape, inputs[1].val)
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", result, spec.Operator, typ, lhs, amount)
	case wasmsimd.AllTrue, wasmsimd.Bitmask:
		return emitWASMV128Reduction(b, newTmp, spec, lhs)
	case wasmsimd.Splat, wasmsimd.ReplaceLane:
		scalar := inputs[len(inputs)-1]
		value := scalar.val
		element := spec.Shape.Element
		if scalar.typ != LLVMType(element) {
			narrowed := newTmp()
			fmt.Fprintf(b, "  %%%s = trunc %s %s to %s\n", narrowed, scalar.typ, value, element)
			value = "%" + narrowed
		}
		if spec.Emission == wasmsimd.Splat {
			vector := emitWASMV128Splat(b, newTmp, spec.Shape, value)
			return wasmValue{typ: wasmV128CoreType, val: cast(vector, resultType, wasmV128CoreType)}
		}
		fmt.Fprintf(b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n",
			result, typ, lhs, element, value, ins.Args[1].Imm)
	case wasmsimd.ExtractLane:
		element := spec.Shape.Element
		fmt.Fprintf(b, "  %%%s = extractelement %s %s, i32 %d\n", result, typ, lhs, ins.Args[1].Imm)
		value := "%" + result
		if spec.Operator != "" {
			extended := newTmp()
			fmt.Fprintf(b, "  %%%s = %s %s %s to %s\n", extended, spec.Operator, element, value, spec.ResultType())
			value = "%" + extended
		}
		return wasmValue{typ: LLVMType(spec.ResultType()), val: value}
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

func emitWASMByteSwizzle(b *strings.Builder, newTmp func() string, typ, source, indices string) string {
	vector := "poison"
	var result string
	for lane := 0; lane < 16; lane++ {
		index, fits, bounded := newTmp(), newTmp(), newTmp()
		fromSource, selected := newTmp(), newTmp()
		result = newTmp()
		fmt.Fprintf(b, "  %%%s = extractelement %s %s, i32 %d\n", index, typ, indices, lane)
		fmt.Fprintf(b, "  %%%s = icmp ult i8 %%%s, 16\n", fits, index)
		// Keep even the speculative extraction in bounds. LLVM may lower
		// dynamic vector indexing to a temporary stack read on baseline Wasm.
		fmt.Fprintf(b, "  %%%s = and i8 %%%s, 15\n", bounded, index)
		fmt.Fprintf(b, "  %%%s = extractelement %s %s, i8 %%%s\n", fromSource, typ, source, bounded)
		fmt.Fprintf(b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", selected, fits, fromSource)
		fmt.Fprintf(b, "  %%%s = insertelement %s %s, i8 %%%s, i32 %d\n", result, typ, vector, selected, lane)
		vector = "%" + result
	}
	return result
}

func emitWASMV128Conversion(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, result, input string) string {
	conversion := spec.Conversion
	source := spec.InputLaneType()
	if source != conversion.InputType {
		picked := newTmp()
		fmt.Fprintf(b, "  %%%s = shufflevector %s %s, %s poison, <%d x i32> <%s>\n",
			picked, source, input, source, conversion.Lanes, wasmV128ShuffleIndices(conversion.Lanes, 0, 1))
		input = "%" + picked
	}
	if conversion.Intrinsic != "" {
		fmt.Fprintf(b, "  %%%s = call %s @%s(%s %s)\n",
			result, conversion.ResultType, conversion.Intrinsic, conversion.InputType, input)
	} else {
		fmt.Fprintf(b, "  %%%s = %s %s %s to %s\n", result, spec.Operator, conversion.InputType, input, conversion.ResultType)
	}
	if conversion.ResultType != spec.Shape.LaneType {
		padded := newTmp()
		count := 128 / spec.Shape.LaneBits
		fmt.Fprintf(b, "  %%%s = shufflevector %s %%%s, %s zeroinitializer, <%d x i32> <%s>\n",
			padded, conversion.ResultType, result, conversion.ResultType, count, wasmV128ShuffleIndices(count, 0, 1))
		return padded
	}
	return result
}

func wasmV128ShuffleIndices(count, first, step int) string {
	var mask strings.Builder
	for lane := 0; lane < count; lane++ {
		if lane != 0 {
			mask.WriteString(", ")
		}
		fmt.Fprintf(&mask, "i32 %d", first+lane*step)
	}
	return mask.String()
}

func emitWASMV128IntegerNarrow(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, result, lhs, rhs string) {
	bits := spec.Shape.LaneBits
	count, source := 128/bits, spec.InputLaneType()
	half := fmt.Sprintf("<%d x %s>", count/2, spec.Shape.Element)
	predicates := fmt.Sprintf("<%d x i1>", count/2)
	low, high := int64(0), int64(1)<<bits-1
	if spec.Operator == "signed" {
		limit := int64(1) << (bits - 1)
		low, high = -limit, limit-1
	}
	splat := func(bound int64) string {
		return fmt.Sprintf("splat (i%d %d)", bits*2, bound)
	}
	lower, upper := splat(low), splat(high)
	narrow := func(input string) string {
		clamp := func(input, predicate, bound string) string {
			test, output := newTmp(), newTmp()
			fmt.Fprintf(b, "  %%%s = icmp %s %s %s, %s\n", test, predicate, source, input, bound)
			fmt.Fprintf(b, "  %%%s = select %s %%%s, %s %s, %s %s\n", output, predicates, test, source, bound, source, input)
			return "%" + output
		}
		// Both output forms clamp signed input lanes before reducing width.
		input = clamp(input, "slt", lower)
		input = clamp(input, "sgt", upper)
		output := newTmp()
		fmt.Fprintf(b, "  %%%s = trunc %s %s to %s\n", output, source, input, half)
		return "%" + output
	}
	left, right := narrow(lhs), narrow(rhs)
	fmt.Fprintf(b, "  %%%s = shufflevector %s %s, %s %s, <%d x i32> <%s>\n",
		result, half, left, half, right, count, wasmV128ShuffleIndices(count, 0, 1))
}

func emitWASMV128IntegerWiden(b *strings.Builder, newTmp func() string, spec wasmsimd.Form, lhs, rhs string) string {
	source := spec.InputLaneType()
	if spec.Widening == wasmsimd.AdjacentPairs {
		// Generic IR keeps this legal without a mandatory SIMD backend.
		// LLVM selects extadd_pairwise when the target has SIMD128.
		return emitWASMV128WidenedPairSum(b, newTmp, source, lhs, spec.Shape, spec.Operator)
	}
	first := 0
	if spec.Widening == wasmsimd.HighHalf {
		first = 128 / spec.Shape.LaneBits
	}
	left := emitWASMV128WidenedLanes(b, newTmp, source, lhs, spec.Shape, first, 1, spec.Operator)
	if rhs == "" {
		return left
	}
	right := emitWASMV128WidenedLanes(b, newTmp, source, rhs, spec.Shape, first, 1, spec.Operator)
	result := newTmp()
	fmt.Fprintf(b, "  %%%s = mul %s %s, %s\n", result, spec.Shape.LaneType, left, right)
	return "%" + result
}

func wasmV128IntegerLiteral(lanes, bits int, value uint64) string {
	lane := fmt.Sprintf("i%d %d", bits, value)
	return "<" + strings.Repeat(lane+", ", lanes-1) + lane + ">"
}

func emitWASMV128CanonicalNaN(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, value string) string {
	// LLVM can fold arithmetic to an operand when the operand is aliased or
	// another input is an identity. Check the lane bits after the operation
	// so a dynamic signaling NaN still becomes a valid Wasm arithmetic NaN.
	bits := shape.LaneBits
	signless, infinity, canonical := wasmFloatNaNBits(bits)
	splat := func(bitsValue uint64) string {
		return wasmV128IntegerLiteral(128/bits, bits, bitsValue)
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
	return emitWASMV128Splat(b, newTmp, shape, count)
}

func emitWASMV128Splat(b *strings.Builder, newTmp func() string, shape wasmsimd.Shape, element string) string {
	seed, splat := newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = insertelement %s poison, %s %s, i32 0\n", seed, shape.LaneType, shape.Element, element)
	fmt.Fprintf(b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n",
		splat, shape.LaneType, seed, shape.LaneType, 128/shape.LaneBits)
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
