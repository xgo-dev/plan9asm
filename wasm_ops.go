package plan9asm

// Go's wasm MOVB/H/W/D names select unsigned memory widths. The operand
// values themselves are 64-bit; no signed/U move variants exist in its table.
var wasmMoveTypes = map[string]LLVMType{
	"MOVB": I8,
	"MOVH": I16,
	"MOVW": I32,
	"MOVD": I64,
}

type wasmIntegerOp struct {
	typ LLVMType
	op  string
}

type wasmFloatUnaryOp struct {
	typ       LLVMType
	intrinsic string
}

var wasmFloatUnaryOps = map[string]wasmFloatUnaryOp{
	"F32ABS":     {LLVMType("float"), "fabs"},
	"F32NEG":     {LLVMType("float"), ""},
	"F32CEIL":    {LLVMType("float"), "ceil"},
	"F32FLOOR":   {LLVMType("float"), "floor"},
	"F32TRUNC":   {LLVMType("float"), "trunc"},
	"F32NEAREST": {LLVMType("float"), "roundeven"},
	"F32SQRT":    {LLVMType("float"), "sqrt"},
	"F64ABS":     {LLVMType("double"), "fabs"},
	"F64NEG":     {LLVMType("double"), ""},
	"F64CEIL":    {LLVMType("double"), "ceil"},
	"F64FLOOR":   {LLVMType("double"), "floor"},
	"F64TRUNC":   {LLVMType("double"), "trunc"},
	"F64NEAREST": {LLVMType("double"), "roundeven"},
	"F64SQRT":    {LLVMType("double"), "sqrt"},
}

var wasmIntegerBinaryOps = map[string]wasmIntegerOp{
	"I32ADD":  {I32, "add"},
	"I32SUB":  {I32, "sub"},
	"I32MUL":  {I32, "mul"},
	"I32AND":  {I32, "and"},
	"I32OR":   {I32, "or"},
	"I32XOR":  {I32, "xor"},
	"I32DIVS": {I32, "sdiv"},
	"I32DIVU": {I32, "udiv"},
	"I32REMS": {I32, "srem"},
	"I32REMU": {I32, "urem"},
	"I32SHL":  {I32, "shl"},
	"I32SHRS": {I32, "ashr"},
	"I32SHRU": {I32, "lshr"},
	"I32ROTL": {I32, "fshl"},
	"I32ROTR": {I32, "fshr"},
	"I64ADD":  {I64, "add"},
	"I64SUB":  {I64, "sub"},
	"I64MUL":  {I64, "mul"},
	"I64AND":  {I64, "and"},
	"I64OR":   {I64, "or"},
	"I64XOR":  {I64, "xor"},
	"I64DIVS": {I64, "sdiv"},
	"I64DIVU": {I64, "udiv"},
	"I64REMS": {I64, "srem"},
	"I64REMU": {I64, "urem"},
	"I64SHL":  {I64, "shl"},
	"I64SHRS": {I64, "ashr"},
	"I64SHRU": {I64, "lshr"},
	"I64ROTL": {I64, "fshl"},
	"I64ROTR": {I64, "fshr"},
}

var wasmIntegerCompareOps = map[string]wasmIntegerOp{
	"I32EQ":  {I32, "eq"},
	"I32NE":  {I32, "ne"},
	"I32LTS": {I32, "slt"},
	"I32LTU": {I32, "ult"},
	"I32GTS": {I32, "sgt"},
	"I32GTU": {I32, "ugt"},
	"I32LES": {I32, "sle"},
	"I32LEU": {I32, "ule"},
	"I32GES": {I32, "sge"},
	"I32GEU": {I32, "uge"},
	"I64EQ":  {I64, "eq"},
	"I64NE":  {I64, "ne"},
	"I64LTS": {I64, "slt"},
	"I64LTU": {I64, "ult"},
	"I64GTS": {I64, "sgt"},
	"I64GTU": {I64, "ugt"},
	"I64LES": {I64, "sle"},
	"I64LEU": {I64, "ule"},
	"I64GES": {I64, "sge"},
	"I64GEU": {I64, "uge"},
}
