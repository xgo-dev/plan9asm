package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type wasmScalarMemoryOp struct {
	access LLVMType
	stack  LLVMType
	store  bool
	signed bool
}

// The access width is independent of the stack carrier. Narrow loads extend
// after reading, and narrow stores truncate only after checking the carrier.
var wasmScalarMemoryOps = map[string]wasmScalarMemoryOp{
	"I32LOAD":    {I32, I32, false, false},
	"I64LOAD":    {I64, I64, false, false},
	"F32LOAD":    {"float", "float", false, false},
	"F64LOAD":    {"double", "double", false, false},
	"I32LOAD8S":  {I8, I32, false, true},
	"I32LOAD8U":  {I8, I32, false, false},
	"I32LOAD16S": {I16, I32, false, true},
	"I32LOAD16U": {I16, I32, false, false},
	"I64LOAD8S":  {I8, I64, false, true},
	"I64LOAD8U":  {I8, I64, false, false},
	"I64LOAD16S": {I16, I64, false, true},
	"I64LOAD16U": {I16, I64, false, false},
	"I64LOAD32S": {I32, I64, false, true},
	"I64LOAD32U": {I32, I64, false, false},
	"I32STORE":   {access: I32, stack: I32, store: true},
	"I64STORE":   {access: I64, stack: I64, store: true},
	"F32STORE":   {access: "float", stack: "float", store: true},
	"F64STORE":   {access: "double", stack: "double", store: true},
	"I32STORE8":  {access: I8, stack: I32, store: true},
	"I32STORE16": {access: I16, stack: I32, store: true},
	"I64STORE8":  {access: I8, stack: I64, store: true},
	"I64STORE16": {access: I16, stack: I64, store: true},
	"I64STORE32": {access: I32, stack: I64, store: true},
}

type wasmScalarMemoryForm struct {
	spec   wasmScalarMemoryOp
	base   Reg
	offset int64
	frame  bool
}

func parseWASMScalarMemory(ins Instr, name string) (wasmScalarMemoryForm, bool, error) {
	spec, found := wasmScalarMemoryOps[name]
	form := wasmScalarMemoryForm{spec: spec}
	if !found {
		return form, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != name || len(ins.Args) > 1 || len(ins.Args) == 0 && !spec.store {
		return form, true, fmt.Errorf("%s requires a scalar memory operand without suffixes", ins.Op)
	}
	// The Go encoder uses zero when the store offset is omitted.
	if len(ins.Args) == 0 {
		return form, true, nil
	}
	switch arg := ins.Args[0]; arg.Kind {
	case OpFP:
		form.frame = true
		return form, true, nil
	case OpImm:
		if arg.ImmIsFloat || arg.ImmRaw != "" {
			return form, true, fmt.Errorf("%s requires a resolved integer memory offset", ins.Op)
		}
		form.offset = arg.Imm
	case OpMem:
		if arg.Mem.OffRaw != "" {
			return form, true, fmt.Errorf("unresolved wasm memory offset %q", arg.Mem.OffRaw)
		}
		// Loads expand Get base; non-SP bases are then wrapped to i32.
		// Stores encode only the offset and take their base from the stack.
		if !spec.store {
			if typ := wasmDefaultRegisterType(arg.Mem.Base); typ != I32 && typ != I64 {
				return form, true, fmt.Errorf("%s requires an integer address register, got %s", ins.Op, arg.Mem.Base)
			}
			form.base = arg.Mem.Base
		}
		form.offset = arg.Mem.Off
	default:
		return form, true, fmt.Errorf("%s expects an FP slot, register memory operand or immediate offset", ins.Op)
	}
	if form.offset < 0 || form.offset > math.MaxUint32 {
		return form, true, fmt.Errorf("%s memory offset %d is outside uint32", ins.Op, form.offset)
	}
	return form, true, nil
}
