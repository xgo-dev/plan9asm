package plan9asm

import (
	"math"
	"strings"
)

func x86FloatAddSubLiteral(ins Instr, spec x86FloatArithmeticSpec) bool {
	return x86FloatArithmeticLiteral(ins, spec.legacy, spec.scalar)
}

// obj6.progedit rewrites legacy scalar ADD/SUB/MUL/DIV constants to
// Float32Sym/Float64Sym. A literal is not caller memory or a register input.
// Both reviewed Go encoders use the same arithmetic rewrite, including ±0.
func x86FloatArithmeticLiteral(ins Instr, legacy, scalar bool) bool {
	if !legacy || !scalar || len(ins.Args) != 2 {
		return false
	}
	operand := ins.Args[0]
	if operand.Kind != OpImm || !operand.ImmIsFloat || operand.ImmRaw != "" {
		return false
	}
	value := math.Float64frombits(uint64(operand.Imm))
	if math.IsInf(value, 0) || math.IsNaN(value) {
		return false // these are not stock Go FLOAT tokens
	}
	if ins.Raw == "" {
		return true // explicitly typed finite value, without source syntax
	}
	_, rest := splitOpcode(ins.Raw)
	arguments := splitTopLevelCSV(rest)
	if len(arguments) != 2 {
		return false
	}
	text := strings.TrimSpace(arguments[0])
	if !strings.HasPrefix(text, "$") {
		return false
	}
	parsed, ok := parseGoFloatLiteral(strings.TrimSpace(text[1:]))
	return ok && math.Float64bits(parsed) == uint64(operand.Imm)
}
