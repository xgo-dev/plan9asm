package wasm

import "github.com/xgo-dev/plan9asm/internal/asm"

type wasmIntegerOp struct {
	typ asm.LLVMType
	op  string
}

type wasmMemoryLoadOp struct {
	loadType   asm.LLVMType
	resultType asm.LLVMType
	signed     bool
}

type wasmMemoryStoreOp struct {
	storeType asm.LLVMType
}

var wasmIntegerBinaryOps = map[string]wasmIntegerOp{
	"I32ADD":  {asm.I32, "add"},
	"I32SUB":  {asm.I32, "sub"},
	"I32MUL":  {asm.I32, "mul"},
	"I32AND":  {asm.I32, "and"},
	"I32OR":   {asm.I32, "or"},
	"I32XOR":  {asm.I32, "xor"},
	"I32DIVS": {asm.I32, "sdiv"},
	"I32DIVU": {asm.I32, "udiv"},
	"I32REMS": {asm.I32, "srem"},
	"I32REMU": {asm.I32, "urem"},
	"I32SHL":  {asm.I32, "shl"},
	"I32SHRS": {asm.I32, "ashr"},
	"I32SHRU": {asm.I32, "lshr"},
	"I64ADD":  {asm.I64, "add"},
	"I64SUB":  {asm.I64, "sub"},
	"I64MUL":  {asm.I64, "mul"},
	"I64AND":  {asm.I64, "and"},
	"I64OR":   {asm.I64, "or"},
	"I64XOR":  {asm.I64, "xor"},
	"I64DIVS": {asm.I64, "sdiv"},
	"I64DIVU": {asm.I64, "udiv"},
	"I64REMS": {asm.I64, "srem"},
	"I64REMU": {asm.I64, "urem"},
	"I64SHL":  {asm.I64, "shl"},
	"I64SHRS": {asm.I64, "ashr"},
	"I64SHRU": {asm.I64, "lshr"},
}

var wasmIntegerCompareOps = map[string]wasmIntegerOp{
	"I32EQ":  {asm.I32, "eq"},
	"I32NE":  {asm.I32, "ne"},
	"I32LTS": {asm.I32, "slt"},
	"I32LTU": {asm.I32, "ult"},
	"I32GTS": {asm.I32, "sgt"},
	"I32GTU": {asm.I32, "ugt"},
	"I32LES": {asm.I32, "sle"},
	"I32LEU": {asm.I32, "ule"},
	"I32GES": {asm.I32, "sge"},
	"I32GEU": {asm.I32, "uge"},
	"I64EQ":  {asm.I64, "eq"},
	"I64NE":  {asm.I64, "ne"},
	"I64LTS": {asm.I64, "slt"},
	"I64LTU": {asm.I64, "ult"},
	"I64GTS": {asm.I64, "sgt"},
	"I64GTU": {asm.I64, "ugt"},
	"I64LES": {asm.I64, "sle"},
	"I64LEU": {asm.I64, "ule"},
	"I64GES": {asm.I64, "sge"},
	"I64GEU": {asm.I64, "uge"},
}

var wasmMemoryLoadOps = map[string]wasmMemoryLoadOp{
	"I32LOAD":    {asm.I32, asm.I32, false},
	"I32LOAD8S":  {asm.I8, asm.I32, true},
	"I32LOAD8U":  {asm.I8, asm.I32, false},
	"I32LOAD16S": {asm.I16, asm.I32, true},
	"I32LOAD16U": {asm.I16, asm.I32, false},
	"I64LOAD":    {asm.I64, asm.I64, false},
	"I64LOAD8S":  {asm.I8, asm.I64, true},
	"I64LOAD8U":  {asm.I8, asm.I64, false},
	"I64LOAD16S": {asm.I16, asm.I64, true},
	"I64LOAD16U": {asm.I16, asm.I64, false},
	"I64LOAD32S": {asm.I32, asm.I64, true},
	"I64LOAD32U": {asm.I32, asm.I64, false},
}

var wasmMemoryStoreOps = map[string]wasmMemoryStoreOp{
	"I32STORE":   {asm.I32},
	"I32STORE8":  {asm.I8},
	"I32STORE16": {asm.I16},
	"I64STORE":   {asm.I64},
	"I64STORE8":  {asm.I8},
	"I64STORE16": {asm.I16},
	"I64STORE32": {asm.I32},
}
