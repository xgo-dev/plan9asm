package plan9asm

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type wasmConversionOp struct {
	source, result LLVMType
	instruction    string
	narrow         LLVMType
	intrinsic      string
	traps          bool
}

// Each source opcode names a stack conversion, with no explicit operands.
// Float/integer conversions share the same width and signedness dimensions.
var wasmConversionOps = func() map[string]wasmConversionOp {
	ops := map[string]wasmConversionOp{
		"I32WRAPI64":        {source: I64, result: I32, instruction: "trunc"},
		"I64EXTENDI32S":     {source: I32, result: I64, instruction: "sext"},
		"I64EXTENDI32U":     {source: I32, result: I64, instruction: "zext"},
		"I32EXTEND8S":       {source: I32, result: I32, instruction: "sext", narrow: I8},
		"I32EXTEND16S":      {source: I32, result: I32, instruction: "sext", narrow: I16},
		"I64EXTEND8S":       {source: I64, result: I64, instruction: "sext", narrow: I8},
		"I64EXTEND16S":      {source: I64, result: I64, instruction: "sext", narrow: I16},
		"I64EXTEND32S":      {source: I64, result: I64, instruction: "sext", narrow: I32},
		"F32DEMOTEF64":      {source: "double", result: "float", instruction: "fptrunc"},
		"F64PROMOTEF32":     {source: "float", result: "double", instruction: "fpext"},
		"I32REINTERPRETF32": {source: "float", result: I32, instruction: "bitcast"},
		"I64REINTERPRETF64": {source: "double", result: I64, instruction: "bitcast"},
		"F32REINTERPRETI32": {source: I32, result: "float", instruction: "bitcast"},
		"F64REINTERPRETI64": {source: I64, result: "double", instruction: "bitcast"},
	}
	for _, integer := range []struct {
		bits int
		typ  LLVMType
	}{{32, I32}, {64, I64}} {
		for _, float := range []struct {
			bits int
			typ  LLVMType
		}{{32, "float"}, {64, "double"}} {
			for _, sign := range []struct {
				suffix, fpToInt, intToFP string
			}{
				{"S", "fptosi", "sitofp"},
				{"U", "fptoui", "uitofp"},
			} {
				suffix := fmt.Sprintf(".%s.f%d", integer.typ, float.bits)
				name := fmt.Sprintf("I%dTRUNCF%d%s", integer.bits, float.bits, sign.suffix)
				ops[name] = wasmConversionOp{
					source: float.typ, result: integer.typ, instruction: sign.fpToInt,
					traps: true,
				}
				name = fmt.Sprintf("I%dTRUNCSATF%d%s", integer.bits, float.bits, sign.suffix)
				ops[name] = wasmConversionOp{
					source: float.typ, result: integer.typ,
					intrinsic: "llvm." + sign.fpToInt + ".sat" + suffix,
				}
				name = fmt.Sprintf("F%dCONVERTI%d%s", float.bits, integer.bits, sign.suffix)
				ops[name] = wasmConversionOp{source: integer.typ, result: float.typ, instruction: sign.intToFP}
			}
		}
	}
	return ops
}()

// WASMScalarConversionOpcodes reports the names registered by the scalar
// conversion grammar. Operand and execution coverage are checked separately.
func WASMScalarConversionOpcodes() []string {
	names := make([]string, 0, len(wasmConversionOps))
	for name := range wasmConversionOps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parseWASMConversion(ins Instr) (wasmConversionOp, bool, error) {
	op := normalizeInstructionOpcode(ins.Op)
	spec, found := wasmConversionOps[op]
	if found && (strings.ToUpper(string(ins.Op)) != op || len(ins.Args) != 0) {
		return spec, true, fmt.Errorf("%s is a zero-operand WebAssembly stack instruction without suffixes", ins.Op)
	}
	return spec, found, nil
}

func (spec wasmConversionOp) emit(b *strings.Builder, value wasmValue, newTmp func() string, newLabel func(string) string) wasmValue {
	result := newTmp()
	if spec.intrinsic != "" {
		fmt.Fprintf(b, "  %%%s = call %s @%s(%s %s)\n", result, spec.result, spec.intrinsic, value.typ, value.val)
		return wasmValue{typ: spec.result, val: "%" + result}
	}
	if spec.traps {
		// LLVM can discard an unused fptosi/fptoui or Wasm conversion
		// intrinsic. Keep the source trap as an explicit side effect.
		spec.emitTrapCheck(b, value, newTmp, newLabel)
	}
	if spec.narrow != "" {
		narrow := newTmp()
		fmt.Fprintf(b, "  %%%s = trunc %s %s to %s\n", narrow, value.typ, value.val, spec.narrow)
		value = wasmValue{typ: spec.narrow, val: "%" + narrow}
	}
	fmt.Fprintf(b, "  %%%s = %s %s %s to %s\n", result, spec.instruction, value.typ, value.val, spec.result)
	return wasmValue{typ: spec.result, val: "%" + result}
}

func (spec wasmConversionOp) emitTrapCheck(b *strings.Builder, value wasmValue, newTmp func() string, newLabel func(string) string) {
	// Bounds apply after rounding toward zero. Only double -> signed i32
	// can represent a fraction between the signed minimum and minimum-1.
	bits := 32
	if spec.result == I64 {
		bits = 64
	}
	lower, upper, predicate := -1.0, math.Ldexp(1, bits), "ogt"
	if spec.instruction == "fptosi" {
		upper = math.Ldexp(1, bits-1)
		lower, predicate = -upper, "oge"
		if spec.source == "double" && spec.result == I32 {
			lower, predicate = lower-1, "ogt"
		}
	}
	above, below, valid := newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = fcmp %s %s %s, 0x%016X\n", above, predicate, value.typ, value.val, math.Float64bits(lower))
	fmt.Fprintf(b, "  %%%s = fcmp olt %s %s, 0x%016X\n", below, value.typ, value.val, math.Float64bits(upper))
	fmt.Fprintf(b, "  %%%s = and i1 %%%s, %%%s\n", valid, above, below)
	emitWASMTrapUnless(b, valid, newLabel)
}

func emitWASMTrapUnless(b *strings.Builder, valid string, newLabel func(string) string) {
	trap, next := newLabel("wasm_trap"), newLabel("wasm_valid")
	fmt.Fprintf(b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", valid, next, trap, trap)
	emitWASMTrap(b)
	fmt.Fprintf(b, "%s:\n", next)
}

func emitWASMTrap(b *strings.Builder) {
	// A Wasm trap is observable even when the surrounding IR is optimized.
	b.WriteString("  call void @llvm.trap()\n  unreachable\n")
}
