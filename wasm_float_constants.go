package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

var wasmFloatConstantTypes = map[string]LLVMType{
	"F32CONST": "float",
	"F64CONST": "double",
}

type wasmFloatConstant struct {
	typ  LLVMType
	bits uint64
}

func parseWASMFloatConstant(ins Instr, name string) (wasmFloatConstant, bool, error) {
	typ, found := wasmFloatConstantTypes[name]
	constant := wasmFloatConstant{typ: typ}
	if !found {
		return constant, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != name || len(ins.Args) != 1 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return constant, true, fmt.Errorf("%s expects one resolved floating immediate without a suffix", ins.Op)
	}
	operand := ins.Args[0]
	constant.bits = uint64(operand.Imm)
	if typ == "float" {
		if !operand.ImmIsFloat {
			return constant, true, fmt.Errorf("%s expects one floating immediate", ins.Op)
		}
		// cmd/asm parses a float64 first and rounds it to the stored width.
		constant.bits = uint64(math.Float32bits(float32(math.Float64frombits(constant.bits))))
	}
	// F64Const also accepts the previously supported raw 64-bit immediate.
	return constant, true, nil
}

func (constant wasmFloatConstant) value() wasmValue {
	if constant.typ == "float" {
		return wasmValue{typ: constant.typ, val: fmt.Sprintf("bitcast (i32 %d to float)", constant.bits)}
	}
	return wasmValue{typ: constant.typ, val: fmt.Sprintf("0x%016X", constant.bits)}
}
