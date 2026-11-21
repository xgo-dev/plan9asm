package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type wasmMemoryOp struct {
	access LLVMType
	stack  LLVMType
	store  bool
	signed bool
}

// The access width is independent of the stack carrier. Narrow loads extend
// after reading, and narrow stores truncate only after checking the carrier.
var wasmMemoryOps = map[string]wasmMemoryOp{
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
	"V128LOAD":   {access: wasmV128CoreType, stack: wasmV128CoreType},
	"V128STORE":  {access: wasmV128CoreType, stack: wasmV128CoreType, store: true},
}

type wasmMemoryForm struct {
	spec   wasmMemoryOp
	base   Reg
	offset int64
	frame  bool
}

func parseWASMMemory(ins Instr, name string) (wasmMemoryForm, bool, error) {
	spec, found := wasmMemoryOps[name]
	form := wasmMemoryForm{spec: spec}
	if !found {
		return form, false, nil
	}
	args := ins.Args
	if spec.store && spec.access == wasmV128CoreType && len(args) != 0 {
		// Go's V128Store encoder reads To.Offset, but the unary spelling
		// populates From. An explicit offset belongs in the destination.
		if zero := args[0]; zero.Kind != OpImm || zero.Imm != 0 || zero.ImmIsFloat || zero.ImmRaw != "" {
			return form, true, fmt.Errorf("%s expects a zero offset or the form $0,destination", ins.Op)
		}
		args = args[1:]
	}
	if strings.ToUpper(string(ins.Op)) != name || len(args) > 1 || len(args) == 0 && !spec.store {
		return form, true, fmt.Errorf("%s requires a memory operand without suffixes", ins.Op)
	}
	// The Go encoder uses zero when the store offset is omitted.
	if len(args) == 0 {
		return form, true, nil
	}
	switch arg := args[0]; arg.Kind {
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

// Check the whole access before LLVM can scalarize a vector memory operation.
// An out-of-bounds vector store must trap before writing any of its bytes.
func emitWASMVectorMemoryBounds(b *strings.Builder, base string, offset int64, newTmp func() string, newLabel func(string) string) {
	address, end := newTmp(), newTmp()
	pages, widePages, size, valid := newTmp(), newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", address, base)
	fmt.Fprintf(b, "  %%%s = add i64 %%%s, %d\n", end, address, offset+16)
	fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.size.i32(i32 0)\n", pages)
	fmt.Fprintf(b, "  %%%s = zext i32 %%%s to i64\n", widePages, pages)
	fmt.Fprintf(b, "  %%%s = shl i64 %%%s, 16\n", size, widePages)
	fmt.Fprintf(b, "  %%%s = icmp ule i64 %%%s, %%%s\n", valid, end, size)
	emitWASMTrapUnless(b, valid, newLabel)
}
