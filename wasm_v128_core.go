package plan9asm

import (
	"fmt"
	"strings"
)

// Reuse the existing V-register carrier. These bitwise operations have one
// fixed 128-bit type; they do not introduce scalar/vector casts or memory.
const wasmV128CoreType LLVMType = "<4 x i32>"

type wasmV128CoreOp struct {
	inputs     int
	operation  string
	laneBits   int
	saturating bool
}

var wasmV128CoreOps = map[string]wasmV128CoreOp{
	"V128CONST":     {operation: "const"},
	"V128NOT":       {inputs: 1, operation: "not"},
	"V128AND":       {inputs: 2, operation: "and"},
	"V128ANDNOT":    {inputs: 2, operation: "andnot"},
	"V128OR":        {inputs: 2, operation: "or"},
	"V128XOR":       {inputs: 2, operation: "xor"},
	"V128BITSELECT": {inputs: 3, operation: "bitselect"},
	"V128ANYTRUE":   {inputs: 1, operation: "anytrue"},

	"I8X16ADD":     {inputs: 2, operation: "add", laneBits: 8},
	"I8X16ADDSATS": {inputs: 2, operation: "sadd.sat", laneBits: 8, saturating: true},
	"I8X16ADDSATU": {inputs: 2, operation: "uadd.sat", laneBits: 8, saturating: true},
	"I8X16SUB":     {inputs: 2, operation: "sub", laneBits: 8},
	"I8X16SUBSATS": {inputs: 2, operation: "ssub.sat", laneBits: 8, saturating: true},
	"I8X16SUBSATU": {inputs: 2, operation: "usub.sat", laneBits: 8, saturating: true},
	"I16X8ADD":     {inputs: 2, operation: "add", laneBits: 16},
	"I16X8ADDSATS": {inputs: 2, operation: "sadd.sat", laneBits: 16, saturating: true},
	"I16X8ADDSATU": {inputs: 2, operation: "uadd.sat", laneBits: 16, saturating: true},
	"I16X8SUB":     {inputs: 2, operation: "sub", laneBits: 16},
	"I16X8SUBSATS": {inputs: 2, operation: "ssub.sat", laneBits: 16, saturating: true},
	"I16X8SUBSATU": {inputs: 2, operation: "usub.sat", laneBits: 16, saturating: true},
	"I16X8MUL":     {inputs: 2, operation: "mul", laneBits: 16},
	"I32X4ADD":     {inputs: 2, operation: "add", laneBits: 32},
	"I32X4SUB":     {inputs: 2, operation: "sub", laneBits: 32},
	"I32X4MUL":     {inputs: 2, operation: "mul", laneBits: 32},
	"I64X2ADD":     {inputs: 2, operation: "add", laneBits: 64},
	"I64X2SUB":     {inputs: 2, operation: "sub", laneBits: 64},
	"I64X2MUL":     {inputs: 2, operation: "mul", laneBits: 64},
}

func (op wasmV128CoreOp) laneType() LLVMType {
	return LLVMType(fmt.Sprintf("<%d x i%d>", 128/op.laneBits, op.laneBits))
}

func (op wasmV128CoreOp) intrinsic() string {
	return fmt.Sprintf("llvm.%s.v%di%d", op.operation, 128/op.laneBits, op.laneBits)
}

func (op wasmV128CoreOp) resultType() LLVMType {
	if op.operation == "anytrue" {
		return I32
	}
	return wasmV128CoreType
}

func parseWASMV128Core(ins Instr) (wasmV128CoreOp, bool, error) {
	name := normalizeInstructionOpcode(ins.Op)
	spec, found := wasmV128CoreOps[name]
	if !found {
		return spec, false, nil
	}
	operands := 0
	if spec.operation == "const" {
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
func emitWASMV128Core(b *strings.Builder, newTmp func() string, spec wasmV128CoreOp, ins Instr, inputs []wasmValue) wasmValue {
	if spec.laneBits != 0 {
		return emitWASMV128IntegerBinary(b, newTmp, spec, inputs[0], inputs[1])
	}
	if spec.operation == "const" {
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
	switch spec.operation {
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
		result = binary(spec.operation, inputs[0].val, inputs[1].val)
	}
	return wasmValue{typ: spec.resultType(), val: result}
}

func emitWASMV128IntegerBinary(b *strings.Builder, newTmp func() string, spec wasmV128CoreOp, lhs, rhs wasmValue) wasmValue {
	typ := spec.laneType()
	cast := func(value string, from, to LLVMType) string {
		if from == to {
			return value
		}
		result := newTmp()
		fmt.Fprintf(b, "  %%%s = bitcast %s %s to %s\n", result, from, value, to)
		return "%" + result
	}
	a, c := cast(lhs.val, wasmV128CoreType, typ), cast(rhs.val, wasmV128CoreType, typ)
	result := newTmp()
	if spec.saturating {
		fmt.Fprintf(b, "  %%%s = call %s @%s(%s %s, %s %s)\n", result, typ, spec.intrinsic(), typ, a, typ, c)
	} else {
		// Unflagged LLVM integer arithmetic wraps separately in each lane.
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", result, spec.operation, typ, a, c)
	}
	return wasmValue{typ: wasmV128CoreType, val: cast("%"+result, typ, wasmV128CoreType)}
}
