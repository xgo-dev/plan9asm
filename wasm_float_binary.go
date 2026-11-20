package plan9asm

import (
	"fmt"
	"strings"
)

// Go's scalar floating binary families share pure, zero-operand stack grammar.
// Comparisons produce i32; arithmetic and min/max retain the operand width.
type wasmFloatBinaryOp struct {
	typ       LLVMType
	predicate string
	intrinsic string
	operation string
}

var wasmFloatBinaryOps = map[string]wasmFloatBinaryOp{
	"F32EQ":  {typ: "float", predicate: "oeq"},
	"F32NE":  {typ: "float", predicate: "une"},
	"F32LT":  {typ: "float", predicate: "olt"},
	"F32GT":  {typ: "float", predicate: "ogt"},
	"F32LE":  {typ: "float", predicate: "ole"},
	"F32GE":  {typ: "float", predicate: "oge"},
	"F64EQ":  {typ: "double", predicate: "oeq"},
	"F64NE":  {typ: "double", predicate: "une"},
	"F64LT":  {typ: "double", predicate: "olt"},
	"F64GT":  {typ: "double", predicate: "ogt"},
	"F64LE":  {typ: "double", predicate: "ole"},
	"F64GE":  {typ: "double", predicate: "oge"},
	"F32MIN": {typ: "float", intrinsic: "minimum"},
	"F32MAX": {typ: "float", intrinsic: "maximum"},
	"F64MIN": {typ: "double", intrinsic: "minimum"},
	"F64MAX": {typ: "double", intrinsic: "maximum"},
}

var wasmFloatArithmeticOps = map[string]wasmFloatBinaryOp{
	"F32ADD": {typ: "float", operation: "fadd"},
	"F32SUB": {typ: "float", operation: "fsub"},
	"F32MUL": {typ: "float", operation: "fmul"},
	"F32DIV": {typ: "float", operation: "fdiv"},
	"F64ADD": {typ: "double", operation: "fadd"},
	"F64SUB": {typ: "double", operation: "fsub"},
	"F64MUL": {typ: "double", operation: "fmul"},
	"F64DIV": {typ: "double", operation: "fdiv"},
}

func wasmFloatBinaryProperties(op string) (wasmFloatBinaryOp, bool) {
	if spec, found := wasmFloatBinaryOps[op]; found {
		return spec, true
	}
	spec, found := wasmFloatArithmeticOps[op]
	return spec, found
}

func (op wasmFloatBinaryOp) resultType() LLVMType {
	if op.predicate != "" {
		return I32
	}
	return op.typ
}

func parseWASMFloatBinary(ins Instr) (wasmFloatBinaryOp, bool, error) {
	op := normalizeInstructionOpcode(ins.Op)
	spec, found := wasmFloatBinaryProperties(op)
	if found && (strings.ToUpper(string(ins.Op)) != op || len(ins.Args) != 0) {
		return spec, true, fmt.Errorf("%s is a zero-operand WebAssembly stack instruction without suffixes", ins.Op)
	}
	return spec, found, nil
}
