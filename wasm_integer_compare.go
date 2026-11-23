package plan9asm

import (
	"fmt"
	"strings"
)

type wasmIntegerComparisonOp struct {
	typ       LLVMType
	predicate string
	arity     int
}

var wasmIntegerCompareOps = map[string]wasmIntegerComparisonOp{
	"I32EQ":  {I32, "eq", 2},
	"I32NE":  {I32, "ne", 2},
	"I32LTS": {I32, "slt", 2},
	"I32LTU": {I32, "ult", 2},
	"I32GTS": {I32, "sgt", 2},
	"I32GTU": {I32, "ugt", 2},
	"I32LES": {I32, "sle", 2},
	"I32LEU": {I32, "ule", 2},
	"I32GES": {I32, "sge", 2},
	"I32GEU": {I32, "uge", 2},
	"I64EQ":  {I64, "eq", 2},
	"I64NE":  {I64, "ne", 2},
	"I64LTS": {I64, "slt", 2},
	"I64LTU": {I64, "ult", 2},
	"I64GTS": {I64, "sgt", 2},
	"I64GTU": {I64, "ugt", 2},
	"I64LES": {I64, "sle", 2},
	"I64LEU": {I64, "ule", 2},
	"I64GES": {I64, "sge", 2},
	"I64GEU": {I64, "uge", 2},
	"I32EQZ": {I32, "eq", 1},
	"I64EQZ": {I64, "eq", 1},
	"NOT":    {I32, "eq", 1},
}

// Go encodes comparisons from the stack. Its generic assembler accepts up to
// two written operands, which the Wasm encoder ignores, and no suffixes.
func parseWASMIntegerComparison(ins Instr, op string) (wasmIntegerComparisonOp, bool, error) {
	spec, found := wasmIntegerCompareOps[op]
	if found && (strings.ToUpper(string(ins.Op)) != op || len(ins.Args) > 2) {
		return spec, true, fmt.Errorf("%s accepts at most two ignored source operands without suffixes: %q", ins.Op, ins.Raw)
	}
	return spec, found, nil
}
