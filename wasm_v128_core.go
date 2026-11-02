package plan9asm

import (
	"fmt"
	"strings"
)

// Reuse the existing V-register carrier. These bitwise operations have one
// fixed 128-bit type; they do not introduce scalar/vector casts or memory.
const wasmV128CoreType LLVMType = "<4 x i32>"

type wasmV128CoreOp struct {
	inputs    int
	operation string
}

var wasmV128CoreOps = map[string]wasmV128CoreOp{
	"V128CONST":     {0, "const"},
	"V128NOT":       {1, "not"},
	"V128AND":       {2, "and"},
	"V128ANDNOT":    {2, "andnot"},
	"V128OR":        {2, "or"},
	"V128XOR":       {2, "xor"},
	"V128BITSELECT": {3, "bitselect"},
	"V128ANYTRUE":   {1, "anytrue"},
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
