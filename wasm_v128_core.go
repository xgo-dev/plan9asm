package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

// All SIMD lane formats share the same 128-bit register and stack carrier.
const wasmV128CoreType LLVMType = "<4 x i32>"

func wasmV128ResultType(op wasmsimd.Form) LLVMType {
	if op.Operator == "anytrue" {
		return I32
	}
	return wasmV128CoreType
}

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
	return wasmValue{typ: wasmV128ResultType(spec), val: result}
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
	if len(inputs) == 2 {
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
	case wasmsimd.FloatCompare, wasmsimd.FloatSelect:
		predicate := newTmp()
		fmt.Fprintf(b, "  %%%s = fcmp %s %s %s, %s\n", predicate, spec.Operator, typ, lhs, rhs)
		if spec.Emission == wasmsimd.FloatCompare {
			// Wasm's true lanes contain all one bits.
			resultType = LLVMType(spec.Shape.MaskType)
			fmt.Fprintf(b, "  %%%s = sext %s %%%s to %s\n", result, spec.Shape.PredicateType, predicate, resultType)
		} else {
			// Pseudo-min/max choose the first operand on a tie or an unordered comparison.
			fmt.Fprintf(b, "  %%%s = select %s %%%s, %s %s, %s %s\n", result, spec.Shape.PredicateType, predicate, typ, rhs, typ, lhs)
		}
	}
	return wasmValue{typ: wasmV128CoreType, val: cast("%"+result, resultType, wasmV128CoreType)}
}
