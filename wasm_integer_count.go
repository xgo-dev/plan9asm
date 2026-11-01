package plan9asm

import (
	"fmt"
	"strings"
)

type wasmIntegerCountOp struct {
	typ       LLVMType
	intrinsic string
}

// All six Go scalar count operators consume and produce the same integer
// width. CLZ and CTZ are defined for zero: their result is the bit width.
var wasmIntegerCountOps = map[string]wasmIntegerCountOp{
	"I32CLZ":    {I32, "ctlz"},
	"I32CTZ":    {I32, "cttz"},
	"I32POPCNT": {I32, "ctpop"},
	"I64CLZ":    {I64, "ctlz"},
	"I64CTZ":    {I64, "cttz"},
	"I64POPCNT": {I64, "ctpop"},
}

func parseWASMIntegerCount(ins Instr) (wasmIntegerCountOp, bool, error) {
	op := normalizeInstructionOpcode(ins.Op)
	spec, found := wasmIntegerCountOps[op]
	if found && (strings.ToUpper(string(ins.Op)) != op || len(ins.Args) != 0) {
		return spec, true, fmt.Errorf("%s is a zero-operand WebAssembly stack instruction without suffixes", ins.Op)
	}
	return spec, found, nil
}
