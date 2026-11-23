package plan9asm

import (
	"fmt"
	"math"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

// The memory32 instructions take i32 stack values. Bulk operations convert
// these carriers to LLVM addresses and a fill byte only after validation.
type wasmMemoryBuiltin struct {
	intrinsic    string
	operands     []string
	sourceAccess LLVMType
}

var wasmMemoryBuiltins = map[string]wasmMemoryBuiltin{
	"CURRENTMEMORY": {intrinsic: "memory.size"},
	"GROWMEMORY":    {intrinsic: "memory.grow", operands: []string{"page count"}},
	"MEMORYCOPY": {
		intrinsic: "memmove", sourceAccess: Ptr,
		operands: []string{"destination address", "source address", "length"},
	},
	"MEMORYFILL": {
		intrinsic: "memset", sourceAccess: I8,
		operands: []string{"destination address", "fill value", "length"},
	},
}

func (spec wasmMemoryBuiltin) isBulk() bool {
	return spec.sourceAccess != ""
}

func parseWASMMemoryBuiltin(ins Instr, op string) (wasmMemoryBuiltin, bool, error) {
	spec, found := wasmMemoryBuiltins[op]
	if !found {
		return spec, false, nil
	}
	return spec, true, validateWASMIgnoredStackOperands(ins, op)
}

type wasmMemoryOp struct {
	access LLVMType
	stack  LLVMType
	store  bool
	signed bool
	vector *wasmsimd.MemoryForm
}

// The access width is independent of the stack carrier. Narrow loads extend
// after reading, and narrow stores truncate only after checking the carrier.
var wasmMemoryOps = map[string]wasmMemoryOp{
	"I32LOAD":    {access: I32, stack: I32},
	"I64LOAD":    {access: I64, stack: I64},
	"F32LOAD":    {access: "float", stack: "float"},
	"F64LOAD":    {access: "double", stack: "double"},
	"I32LOAD8S":  {access: I8, stack: I32, signed: true},
	"I32LOAD8U":  {access: I8, stack: I32},
	"I32LOAD16S": {access: I16, stack: I32, signed: true},
	"I32LOAD16U": {access: I16, stack: I32},
	"I64LOAD8S":  {access: I8, stack: I64, signed: true},
	"I64LOAD8U":  {access: I8, stack: I64},
	"I64LOAD16S": {access: I16, stack: I64, signed: true},
	"I64LOAD16U": {access: I16, stack: I64},
	"I64LOAD32S": {access: I32, stack: I64, signed: true},
	"I64LOAD32U": {access: I32, stack: I64},
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

func lookupWASMMemoryOp(name string) (wasmMemoryOp, bool) {
	if spec, ok := wasmMemoryOps[name]; ok {
		return spec, true
	}
	if vector := wasmsimd.LookupMemory(name); vector != nil {
		return wasmMemoryOp{
			access: LLVMType(vector.AccessType), stack: wasmV128CoreType,
			store: vector.Operation == wasmsimd.MemoryStoreLane, vector: vector,
		}, true
	}
	return wasmMemoryOp{}, false
}

func (spec wasmMemoryOp) consumesValue() bool {
	return spec.store || spec.vector != nil && spec.vector.Operation == wasmsimd.MemoryLoadLane
}

func (spec wasmMemoryOp) guardedWidth() int64 {
	if spec.vector != nil {
		return int64(spec.vector.AccessBytes)
	}
	if spec.access == wasmV128CoreType {
		return 16
	}
	return 0
}

type wasmMemoryForm struct {
	spec   wasmMemoryOp
	base   Reg
	offset int64
	frame  bool
	lane   int64
}

func parseWASMMemory(ins Instr, name string) (wasmMemoryForm, bool, error) {
	spec, found := lookupWASMMemoryOp(name)
	form := wasmMemoryForm{spec: spec}
	if !found {
		return form, false, nil
	}
	args := ins.Args
	if spec.vector != nil {
		if spec.vector.HasLaneIndex() {
			if len(args) != 2 {
				return form, true, fmt.Errorf("%s requires an immediate memory offset and a lane index", ins.Op)
			}
			lane := args[1]
			limit := int64(128 / spec.vector.Shape.LaneBits)
			if lane.Kind != OpImm || lane.ImmIsFloat || lane.ImmRaw != "" || lane.Imm < 0 || lane.Imm >= limit {
				return form, true, fmt.Errorf("%s requires a lane index between 0 and %d", ins.Op, limit-1)
			}
			form.lane = lane.Imm
			args = args[:1]
		}
		if len(args) != 1 || args[0].Kind != OpImm {
			return form, true, fmt.Errorf("%s requires an immediate memory offset", ins.Op)
		}
	} else if spec.store && spec.access == wasmV128CoreType && len(args) != 0 {
		// Go's V128Store encoder reads To.Offset, but the unary spelling
		// populates From. An explicit offset belongs in the destination.
		if zero := args[0]; zero.Kind != OpImm || zero.Imm != 0 || zero.ImmIsFloat || zero.ImmRaw != "" {
			return form, true, fmt.Errorf("%s expects a zero offset or the form $0,destination", ins.Op)
		}
		args = args[1:]
	}
	if strings.ToUpper(string(ins.Op)) != name || len(args) > 1 || len(args) == 0 && !spec.store {
		if spec.vector == nil && spec.access != wasmV128CoreType {
			return form, true, fmt.Errorf("%s requires a scalar memory operand without suffixes", ins.Op)
		}
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
func emitWASMVectorMemoryBounds(b *strings.Builder, base string, span int64, newTmp func() string, newLabel func(string) string) {
	size := emitWASMMemoryByteSize(b, newTmp)
	address, end, valid := newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", address, base)
	fmt.Fprintf(b, "  %%%s = add i64 %%%s, %d\n", end, address, span)
	fmt.Fprintf(b, "  %%%s = icmp ule i64 %%%s, %s\n", valid, end, size)
	emitWASMTrapUnless(b, valid, newLabel)
}

func emitWASMMemoryByteSize(b *strings.Builder, newTmp func() string) string {
	pages, widePages, size := newTmp(), newTmp(), newTmp()
	fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.size.i32(i32 0)\n", pages)
	fmt.Fprintf(b, "  %%%s = zext i32 %%%s to i64\n", widePages, pages)
	fmt.Fprintf(b, "  %%%s = shl i64 %%%s, 16\n", size, widePages)
	return "%" + size
}

// LLVM can elide an empty memmove/memset or split a fixed-size operation into
// smaller writes. Check every range first to retain WebAssembly's trap even
// when len is zero, and to leave memory untouched when any range is invalid.
func emitWASMBulkMemoryBounds(b *strings.Builder, length string, newTmp func() string, newLabel func(string) string, addresses ...string) {
	size := emitWASMMemoryByteSize(b, newTmp)
	wideLength := newTmp()
	fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", wideLength, length)
	for _, address := range addresses {
		wideAddress, end, valid := newTmp(), newTmp(), newTmp()
		fmt.Fprintf(b, "  %%%s = zext i32 %s to i64\n", wideAddress, address)
		fmt.Fprintf(b, "  %%%s = add i64 %%%s, %%%s\n", end, wideAddress, wideLength)
		fmt.Fprintf(b, "  %%%s = icmp ule i64 %%%s, %s\n", valid, end, size)
		emitWASMTrapUnless(b, valid, newLabel)
	}
}

func emitWASMVectorMemoryLoad(b *strings.Builder, newTmp func() string, form wasmMemoryForm, loaded, input wasmValue) wasmValue {
	spec := form.spec.vector
	laneType := LLVMType(spec.Shape.LaneType)
	var vector string
	switch spec.Operation {
	case wasmsimd.MemorySplat:
		vector = emitWASMV128Splat(b, newTmp, spec.Shape, loaded.val)
	case wasmsimd.MemoryWiden:
		op := "zext"
		if spec.Signed {
			op = "sext"
		}
		result := newTmp()
		fmt.Fprintf(b, "  %%%s = %s %s %s to %s\n", result, op, loaded.typ, loaded.val, laneType)
		vector = "%" + result
	case wasmsimd.MemoryZero, wasmsimd.MemoryLoadLane:
		base := "zeroinitializer"
		if spec.Operation == wasmsimd.MemoryLoadLane {
			base = emitWASMVectorBitcast(b, newTmp, input.val, input.typ, laneType)
		}
		result := newTmp()
		fmt.Fprintf(b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n",
			result, laneType, base, loaded.typ, loaded.val, form.lane)
		vector = "%" + result
	}
	return wasmValue{typ: wasmV128CoreType, val: emitWASMVectorBitcast(b, newTmp, vector, laneType, wasmV128CoreType)}
}

func emitWASMVectorMemoryStoreLane(b *strings.Builder, newTmp func() string, form wasmMemoryForm, input wasmValue) wasmValue {
	laneType := LLVMType(form.spec.vector.Shape.LaneType)
	lanes := emitWASMVectorBitcast(b, newTmp, input.val, input.typ, laneType)
	result := newTmp()
	fmt.Fprintf(b, "  %%%s = extractelement %s %s, i32 %d\n", result, laneType, lanes, form.lane)
	return wasmValue{typ: form.spec.access, val: "%" + result}
}
