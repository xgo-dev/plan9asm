package plan9asm

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/wasmsimd"
)

type wasmValue struct {
	typ       LLVMType
	val       string
	stackAddr bool
}

type wasmControlLabel struct {
	kind       string
	name       string
	resultType LLVMType
}

func (label wasmControlLabel) branchResult() LLVMType {
	// Loop labels have no parameters in Go's single-result block encoding.
	// The declared result belongs only to the fallthrough out of the loop.
	if label.kind == "loop" {
		return ""
	}
	return label.resultType
}

func wasmBranchTarget(ins Instr, op string, count int, nameAt func(int) string) (int, error) {
	if strings.ToUpper(string(ins.Op)) != op || len(ins.Args) != 1 {
		return 0, fmt.Errorf("%s expects one target without suffixes", ins.Op)
	}
	arg := ins.Args[0]
	var name string
	switch arg.Kind {
	case OpImm:
		if arg.ImmRaw != "" || arg.ImmIsFloat {
			return 0, fmt.Errorf("%s branch depth must be an immediate integer", ins.Op)
		}
		if arg.Imm < 0 || arg.Imm >= int64(count) {
			return 0, fmt.Errorf("branch depth %d exceeds %d active controls", arg.Imm, count)
		}
		return count - 1 - int(arg.Imm), nil
	case OpIdent:
		name = arg.Ident
	case OpLabel, OpSym:
		name = strings.TrimSuffix(arg.Sym, ":")
	default:
		return 0, fmt.Errorf("unsupported branch target %s", arg)
	}
	for i := count - 1; i >= 0; i-- {
		if nameAt(i) == name {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown structured branch target %q", name)
}

type wasmControlFrame struct {
	wasmControlLabel
	startLabel string
	elseLabel  string
	endLabel   string
	baseStack  []wasmValue
	resultSlot string
	inElse     bool
}

type wasmDeadControlFrame struct {
	kind   string
	result LLVMType
}

// Track the lexical nesting below a terminated path. Only a delimiter of the
// surrounding live control may re-enter its alternate path or continuation.
type wasmDeadControls []wasmDeadControlFrame

func (frames *wasmDeadControls) skip(op string, result LLVMType) (bool, error) {
	switch op {
	case "BLOCK", "LOOP", "IF":
		*frames = append(*frames, wasmDeadControlFrame{kind: op, result: result})
	case "END", "ELSE":
		if len(*frames) == 0 {
			return false, nil
		}
		last := len(*frames) - 1
		frame := &(*frames)[last]
		if op == "END" {
			if frame.kind == "IF" && frame.result != "" {
				return true, fmt.Errorf("result-producing If requires Else")
			}
			*frames = (*frames)[:last]
		} else {
			if frame.kind != "IF" {
				return true, fmt.Errorf("Else without matching If")
			}
			frame.kind = "ELSE"
		}
	case "RESUMEPOINT":
		return len(*frames) != 0, nil
	}
	return true, nil
}

func parseWASMControlResult(ins Instr, op string) (LLVMType, error) {
	switch op {
	case "BLOCK", "LOOP", "IF":
	default:
		return "", nil
	}
	if len(ins.Args) == 0 {
		return "", nil
	}
	if len(ins.Args) != 1 {
		return "", fmt.Errorf("%s expects at most one block type", ins.Op)
	}
	operand := ins.Args[0]
	if operand.Kind != OpImm || operand.ImmRaw != "" || operand.ImmIsFloat {
		return "", fmt.Errorf("%s block type must be an immediate integer", ins.Op)
	}
	// Go writes the empty block type for zero and 0x80 minus the
	// immediate for the numeric and vector result types.
	switch operand.Imm {
	case 0:
		return "", nil
	case 1:
		return I32, nil
	case 2:
		return I64, nil
	case 3:
		return "float", nil
	case 4:
		return "double", nil
	case 5:
		return wasmV128CoreType, nil
	default:
		return "", fmt.Errorf("%s has unsupported block type $%d", ins.Op, operand.Imm)
	}
}

func wasmControlResultSlot(index int) string {
	return fmt.Sprintf("wasm_control_result_%d", index)
}

func validateWASMRawReturn(ins Instr, op string) error {
	// Go accepts one- and two-operand source spellings and emits the same
	// return instruction. These operands do not supply the stack result.
	if op == "WASMRETURN" && len(ins.Args) > 2 {
		return fmt.Errorf("Return accepts at most two ignored source operands: %q", ins.Raw)
	}
	return nil
}

func wasmSourceTrap(op string) bool {
	return op == "UNDEF" || op == "UNREACHABLE"
}

func validateWASMStackControlOperands(ins Instr, op string) error {
	if op == "SELECT" || wasmSourceTrap(op) {
		return validateWASMIgnoredStackOperands(ins, op)
	}
	return nil
}

// These encoders obtain their inputs from the operand stack. Go's generic
// assembler accepts up to two written operands and rejects suffixes.
func validateWASMIgnoredStackOperands(ins Instr, op string) error {
	if strings.ToUpper(string(ins.Op)) != op || len(ins.Args) > 2 {
		return fmt.Errorf("%s accepts at most two ignored source operands without suffixes: %q", ins.Op, ins.Raw)
	}
	return nil
}

func wasmPhysicalStackType(typ LLVMType) LLVMType {
	switch typ {
	case I1, I8, I16, Ptr:
		return I32
	default:
		return typ
	}
}

// translateFuncWASM lowers WebAssembly Plan 9 stack instructions into ordinary
// LLVM SSA. The direct ABI maps FP operands through FuncSig.Frame. The Go ABI
// instead recreates the official compiler's linear-memory stack, register
// globals, resumable calls, and unwind return protocol.
func translateFuncWASM(b *strings.Builder, file *File, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, wasmABI WASMABI, annotateSource bool) (err error) {
	useGoStack := wasmABI == WASMABIGo
	goABI := useGoStack && !sig.WASMNative
	// Validate source format before dead-block removal. Pure dead operators may
	// disappear, but malformed source must not acquire an apparent pass.
	var memoryForms map[int]wasmMemoryForm
	var controlResults map[int]LLVMType
	bulkMemory := false
	needsResumePlan := false
	for i, ins := range fn.Instrs {
		op := normalizeInstructionOpcode(ins.Op)
		if err := validateWASMRawReturn(ins, op); err != nil {
			return err
		}
		if err := validateWASMStackControlOperands(ins, op); err != nil {
			return err
		}
		resultType, err := parseWASMControlResult(ins, op)
		if err != nil {
			return err
		}
		if resultType != "" {
			if controlResults == nil {
				controlResults = make(map[int]LLVMType)
			}
			controlResults[i] = resultType
		}
		if op == "RESUMEPOINT" || wasmLocalJumpLabel(ins, op) != "" {
			if !goABI {
				return fmt.Errorf("%s requires the Go WebAssembly ABI", op)
			}
			needsResumePlan = true
		}
		if useGoStack && (op == "CALL" || op == "CALLNORESUME") {
			needsResumePlan = true
		}
		memoryBuiltin, builtinKnown, err := parseWASMMemoryBuiltin(ins, op)
		if err != nil {
			return err
		}
		bulkMemory = bulkMemory || builtinKnown && memoryBuiltin.isBulk()
		form, found, err := parseWASMMemory(ins, op)
		if err != nil {
			return err
		}
		if found {
			if memoryForms == nil {
				memoryForms = make(map[int]wasmMemoryForm)
			}
			memoryForms[i] = form
		}
		if _, _, err := parseWASMIntegerBinary(ins, op); err != nil {
			return err
		}
		if _, _, err := parseWASMIntegerComparison(ins, op); err != nil {
			return err
		}
		if _, _, err := parseWASMFloatBinary(ins); err != nil {
			return err
		}
		if _, _, err := parseWASMFloatConstant(ins, op); err != nil {
			return err
		}
		if _, _, err := parseWASMIntegerCount(ins); err != nil {
			return err
		}
		if _, _, err := parseWASMConversion(ins); err != nil {
			return err
		}
		if _, _, err := parseWASMV128Core(ins, op); err != nil {
			return err
		}
	}
	var resumePlan *wasmResumePlan
	if needsResumePlan {
		resumePlan, err = planWASMResume(fn)
		if err != nil {
			return err
		}
	}
	// LLVM's WebAssembly backend cannot lower blockaddress. Keep this as a
	// lowering invariant so future control-flow or code-pointer work fails here
	// instead of producing IR that only breaks later in llc.
	output := b
	outputStart := b.Len()
	defer func() {
		if err != nil {
			return
		}
		if strings.Contains(output.String()[outputStart:], "blockaddress(") {
			err = fmt.Errorf("wasm lowering emitted unsupported LLVM blockaddress in %s", sig.Name)
		}
	}()

	physicalRet := sig.Ret
	if goABI {
		physicalRet = I32
	}
	fmt.Fprintf(b, "define %s %s(", physicalRet, llvmGlobal(sig.Name))
	argIndex := 0
	if goABI {
		b.WriteString("i32 %pc_b")
		argIndex++
	} else if sig.WASMContext != "" {
		fmt.Fprintf(b, "%s %%wasm_context", sig.WASMContext)
		argIndex++
	}
	for i, typ := range sig.Args {
		if goABI {
			break
		}
		if argIndex > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s %%arg%d", typ, i)
		argIndex++
	}
	b.WriteString(")")
	if sig.Attrs != "" {
		b.WriteString(" " + sig.Attrs)
	}
	if bulkMemory {
		// Linear memory includes byte zero. LLVM otherwise treats a nonempty
		// memmove or memset at that address as undefined and can remove it.
		b.WriteString(" null_pointer_is_valid")
	}
	b.WriteString(" {\nentry:\n")

	var (
		stack           []wasmValue
		regSlots        = make(map[Reg]string)
		regInitialized  = make(map[Reg]bool)
		results         = make([]wasmValue, len(sig.Frame.Results))
		haveResult      = make([]bool, len(sig.Frame.Results))
		tmp             int
		blockTerminated bool
	)
	newTmp := func() string {
		tmp++
		return fmt.Sprintf("wasm%d", tmp)
	}
	push := func(v wasmValue) { stack = append(stack, v) }
	pop := func(op string) (wasmValue, error) {
		if len(stack) == 0 {
			return wasmValue{}, fmt.Errorf("%s: operand stack underflow", op)
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v, nil
	}
	cast := func(v wasmValue, to LLVMType, signed bool) (wasmValue, error) {
		if v.stackAddr {
			return wasmValue{}, fmt.Errorf("cannot cast stack-address marker to %s", to)
		}
		if v.typ == to {
			return v, nil
		}
		name := newTmp()
		switch {
		case v.typ == Ptr && (to == I32 || to == I64):
			fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to %s\n", name, v.val, to)
		case (v.typ == I32 || v.typ == I64) && to == Ptr:
			fmt.Fprintf(b, "  %%%s = inttoptr %s %s to ptr\n", name, v.typ, v.val)
		case (v.typ == I1 || v.typ == I8 || v.typ == I16 || v.typ == I32) && to == I64:
			op := "zext"
			if signed {
				op = "sext"
			}
			fmt.Fprintf(b, "  %%%s = %s %s %s to i64\n", name, op, v.typ, v.val)
		case (v.typ == I1 || v.typ == I8 || v.typ == I16) && to == I32:
			op := "zext"
			if signed {
				op = "sext"
			}
			fmt.Fprintf(b, "  %%%s = %s %s %s to i32\n", name, op, v.typ, v.val)
		case v.typ == I64 && (to == I32 || to == I16 || to == I8 || to == I1):
			fmt.Fprintf(b, "  %%%s = trunc i64 %s to %s\n", name, v.val, to)
		case v.typ == I32 && (to == I16 || to == I8 || to == I1):
			fmt.Fprintf(b, "  %%%s = trunc i32 %s to %s\n", name, v.val, to)
		case v.typ == I16 && (to == I8 || to == I1):
			fmt.Fprintf(b, "  %%%s = trunc i16 %s to %s\n", name, v.val, to)
		case v.typ == I8 && to == I1:
			fmt.Fprintf(b, "  %%%s = trunc i8 %s to i1\n", name, v.val)
		default:
			return wasmValue{}, fmt.Errorf("unsupported wasm cast %s to %s", v.typ, to)
		}
		return wasmValue{typ: to, val: "%" + name}, nil
	}
	var wasmRType LLVMType
	argRegTypes := make(map[Reg]LLVMType, len(sig.ArgRegs))
	for i, reg := range sig.ArgRegs {
		if i < len(sig.Args) {
			argRegTypes[reg] = sig.Args[i]
		}
		if i >= len(sig.Args) || wasmRType != "" || !strings.HasPrefix(strings.ToUpper(string(reg)), "R") {
			continue
		}
		if sig.Args[i] == I32 || sig.Args[i] == I64 {
			wasmRType = sig.Args[i]
		}
	}
	if wasmRType == "" {
		wasmRType = I64
	}
	registerType := func(reg Reg) (LLVMType, error) {
		name := strings.ToUpper(string(reg))
		switch {
		case argRegTypes[reg] != "":
			return argRegTypes[reg], nil
		case useGoStack && name == "SP":
			return I32, nil
		case useGoStack && (name == "CTXT" || name == "G" || strings.HasPrefix(name, "RET")):
			return I64, nil
		case useGoStack && name == "PAUSE":
			return I32, nil
		case name == "CTXT" && sig.WASMContext != "":
			return sig.WASMContext, nil
		case strings.HasPrefix(name, "R"), name == "CTXT", name == "G",
			strings.HasPrefix(name, "RET"), name == "PAUSE":
			return wasmRType, nil
		case name == "PC_B":
			return I32, nil
		case strings.HasPrefix(name, "F"):
			n := 0
			if _, err := fmt.Sscanf(name, "F%d", &n); err != nil {
				return "", fmt.Errorf("invalid wasm register %s", reg)
			}
			if n < 16 {
				return LLVMType("float"), nil
			}
			return LLVMType("double"), nil
		case strings.HasPrefix(name, "V"):
			return LLVMType("<4 x i32>"), nil
		default:
			return "", fmt.Errorf("unsupported wasm register %s", reg)
		}
	}
	for index, ins := range fn.Instrs {
		// A control can be entered on every iteration of an enclosing loop.
		// Use one slot for the entire function, including at LLVM -O0.
		if resultType := controlResults[index]; resultType != "" {
			fmt.Fprintf(b, "  %%%s = alloca %s\n", wasmControlResultSlot(index), resultType)
		}
		for _, arg := range ins.Args {
			var reg Reg
			switch arg.Kind {
			case OpReg:
				reg = arg.Reg
			case OpMem:
				if memoryForms[index].spec.store {
					continue // The store's explicit base spelling does not read a register.
				}
				reg = arg.Mem.Base
			default:
				continue
			}
			if reg == "" || reg == SP || useGoStack && wasmGoGlobalRegister(reg) {
				continue
			}
			if _, ok := regSlots[reg]; ok {
				continue
			}
			typ, err := registerType(reg)
			if err != nil {
				return err
			}
			slot := "wasm_reg_" + strings.ReplaceAll(string(reg), ".", "_")
			regSlots[reg] = slot
			fmt.Fprintf(b, "  %%%s = alloca %s\n", slot, typ)
			fmt.Fprintf(b, "  store %s %s, ptr %%%s\n", typ, llvmZeroValue(typ), slot)
		}
	}
	for i, reg := range sig.ArgRegs {
		if goABI {
			break
		}
		if i >= len(sig.Args) || reg == SP {
			continue
		}
		slot, ok := regSlots[reg]
		if !ok {
			continue
		}
		typ, err := registerType(reg)
		if err != nil {
			return err
		}
		v, err := cast(wasmValue{typ: sig.Args[i], val: fmt.Sprintf("%%arg%d", i)}, typ, false)
		if err != nil {
			return fmt.Errorf("initialize %s from argument %d: %w", reg, i, err)
		}
		fmt.Fprintf(b, "  store %s %s, ptr %%%s\n", typ, v.val, slot)
		regInitialized[reg] = true
	}
	if goABI {
		if slot, ok := regSlots[Reg("PC_B")]; ok {
			fmt.Fprintf(b, "  store i32 %%pc_b, ptr %%%s\n", slot)
			regInitialized[Reg("PC_B")] = true
		}
	}
	if !useGoStack && sig.WASMContext != "" {
		if slot, ok := regSlots[Reg("CTXT")]; ok {
			fmt.Fprintf(b, "  store %s %%wasm_context, ptr %%%s\n", sig.WASMContext, slot)
			regInitialized[Reg("CTXT")] = true
		}
	}
	loadRegister := func(reg Reg) (wasmValue, error) {
		if useGoStack && wasmGoGlobalRegister(reg) {
			typ, err := registerType(reg)
			if err != nil {
				return wasmValue{}, err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = load %s, ptr addrspace(1) %s\n", name, typ, llvmGlobal(wasmGoGlobalName(reg)))
			return wasmValue{typ: typ, val: "%" + name}, nil
		}
		slot, ok := regSlots[reg]
		if !ok {
			return wasmValue{}, fmt.Errorf("register %s is not available", reg)
		}
		if reg == Reg("CTXT") && !regInitialized[reg] {
			return wasmValue{}, fmt.Errorf("CTXT requires an explicit closure-environment ABI input")
		}
		typ, err := registerType(reg)
		if err != nil {
			return wasmValue{}, err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = load %s, ptr %%%s\n", name, typ, slot)
		return wasmValue{typ: typ, val: "%" + name}, nil
	}
	storeRegister := func(reg Reg, value wasmValue) (wasmValue, error) {
		if useGoStack && wasmGoGlobalRegister(reg) {
			typ, err := registerType(reg)
			if err != nil {
				return wasmValue{}, err
			}
			value, err = cast(value, typ, false)
			if err != nil {
				return wasmValue{}, err
			}
			fmt.Fprintf(b, "  store %s %s, ptr addrspace(1) %s\n", typ, value.val, llvmGlobal(wasmGoGlobalName(reg)))
			return value, nil
		}
		slot, ok := regSlots[reg]
		if !ok {
			return wasmValue{}, fmt.Errorf("register %s is not available", reg)
		}
		typ, err := registerType(reg)
		if err != nil {
			return wasmValue{}, err
		}
		value, err = cast(value, typ, false)
		if err != nil {
			return wasmValue{}, err
		}
		fmt.Fprintf(b, "  store %s %s, ptr %%%s\n", typ, value.val, slot)
		regInitialized[reg] = true
		return value, nil
	}
	var addressPtr func(wasmValue, int64) (wasmValue, error)
	goFrameAddress := func(offset int64) (wasmValue, error) {
		sp, err := loadRegister(SP)
		if err != nil {
			return wasmValue{}, err
		}
		return addressPtr(sp, fn.FrameSize+8+offset)
	}
	frameParam := func(arg Operand, width LLVMType) (wasmValue, error) {
		for _, slot := range sig.Frame.Params {
			if slot.Offset != arg.FPOffset {
				continue
			}
			if useGoStack {
				address, err := goFrameAddress(arg.FPOffset)
				if err != nil {
					return wasmValue{}, err
				}
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = load %s, ptr %s, align 1\n", name, width, address.val)
				return wasmValue{typ: width, val: "%" + name}, nil
			}
			if slot.Index < 0 || slot.Index >= len(sig.Args) {
				return wasmValue{}, fmt.Errorf("FP parameter %s has invalid argument index %d", arg, slot.Index)
			}
			value := fmt.Sprintf("%%arg%d", slot.Index)
			if fields := frameSlotFields(slot); len(fields) != 0 {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = extractvalue %s %s%s\n", name, sig.Args[slot.Index], value, frameSlotExtractSuffix(slot))
				value = "%" + name
			}
			return wasmValue{typ: slot.Type, val: value}, nil
		}
		return wasmValue{}, fmt.Errorf("unknown FP parameter %s", arg)
	}
	storeResult := func(arg Operand, value wasmValue) error {
		for i, slot := range sig.Frame.Results {
			if slot.Offset != arg.FPOffset {
				continue
			}
			if useGoStack {
				address, err := goFrameAddress(arg.FPOffset)
				if err != nil {
					return err
				}
				fmt.Fprintf(b, "  store %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
				return nil
			}
			if value.typ != slot.Type {
				fromType := value.typ
				var err error
				value, err = cast(value, slot.Type, false)
				if err != nil {
					return fmt.Errorf("FP result %s has type %s, want %s: %w", arg, fromType, slot.Type, err)
				}
			}
			results[i] = value
			haveResult[i] = true
			return nil
		}
		return fmt.Errorf("unknown FP result %s", arg)
	}
	loadOperand := func(arg Operand, width LLVMType) (wasmValue, error) {
		var v wasmValue
		var err error
		switch arg.Kind {
		case OpFP:
			v, err = frameParam(arg, width)
		case OpFPAddr:
			if !useGoStack {
				return wasmValue{}, fmt.Errorf("linear-memory FP addresses require the Go WebAssembly ABI")
			}
			v, err = goFrameAddress(arg.FPOffset)
		case OpReg:
			v, err = loadRegister(arg.Reg)
		case OpImm:
			v = wasmValue{typ: width, val: fmt.Sprintf("%d", arg.Imm)}
		case OpSym:
			isAddress := strings.HasPrefix(strings.TrimSpace(arg.Sym), "$")
			if isAddress {
				if mem, matched, memErr := parseWASMMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$"))); matched {
					if memErr != nil {
						return wasmValue{}, memErr
					}
					base, loadErr := loadRegister(mem.Base)
					if loadErr != nil {
						return wasmValue{}, loadErr
					}
					v, err = addressPtr(base, mem.Off)
					if err != nil {
						return wasmValue{}, err
					}
					break
				}
			}
			base, offset, ok := parseSBRef(arg.Sym)
			if !ok {
				return wasmValue{}, fmt.Errorf("unsupported wasm symbol address %s", arg)
			}
			base = strings.TrimPrefix(base, "$")
			if isAddress {
				name, function, packed, addressErr := wasmFunctionAddress(file, base, offset, resolve, sigs, wasmABI)
				if addressErr != nil {
					return wasmValue{}, addressErr
				}
				if function {
					v, err = cast(wasmValue{typ: Ptr, val: llvmGlobal(name)}, I64, false)
					if err != nil {
						return wasmValue{}, err
					}
					if packed {
						tmp := newTmp()
						fmt.Fprintf(b, "  %%%s = shl i64 %s, 16\n", tmp, v.val)
						v = wasmValue{typ: I64, val: "%" + tmp}
					}
					if offset != 0 {
						tmp := newTmp()
						fmt.Fprintf(b, "  %%%s = add i64 %s, %d\n", tmp, v.val, offset)
						v = wasmValue{typ: I64, val: "%" + tmp}
					}
					break
				}
			}
			if !strings.ContainsAny(base, "·/.") {
				base = "·" + base
			}
			v = wasmValue{typ: Ptr, val: llvmGlobal(resolve(base))}
			if offset != 0 {
				v, err = addressPtr(v, offset)
				if err != nil {
					return wasmValue{}, err
				}
			}
			if !isAddress {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = load %s, ptr %s, align 1\n", name, width, v.val)
				v = wasmValue{typ: width, val: "%" + name}
			}
		case OpMem:
			if arg.Mem.Base == SP && !useGoStack {
				return wasmValue{}, fmt.Errorf("linear-memory SP operands are not available in the direct Go ABI")
			}
			base, loadErr := loadRegister(arg.Mem.Base)
			if loadErr != nil {
				return wasmValue{}, fmt.Errorf("load %s: %w", arg, loadErr)
			}
			address, addressErr := addressPtr(base, arg.Mem.Off)
			if addressErr != nil {
				return wasmValue{}, addressErr
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = load %s, ptr %s, align 1\n", name, width, address.val)
			v = wasmValue{typ: width, val: "%" + name}
		default:
			return wasmValue{}, fmt.Errorf("unsupported wasm source operand %s", arg)
		}
		if err != nil {
			return wasmValue{}, err
		}
		if v.typ != width && width != "" {
			v, err = cast(v, width, false)
		}
		return v, err
	}
	storeOperand := func(arg Operand, value wasmValue) error {
		switch arg.Kind {
		case OpReg:
			_, err := storeRegister(arg.Reg, value)
			return err
		case OpFP:
			return storeResult(arg, value)
		case OpMem:
			if arg.Mem.Base == SP && !useGoStack {
				return fmt.Errorf("linear-memory SP operands are not available in the direct Go ABI")
			}
			base, err := loadRegister(arg.Mem.Base)
			if err != nil {
				return fmt.Errorf("store %s: %w", arg, err)
			}
			address, err := addressPtr(base, arg.Mem.Off)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  store %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
			return nil
		case OpSym:
			base, offset, ok := parseSBRef(arg.Sym)
			if !ok {
				return fmt.Errorf("unsupported wasm symbol destination %s", arg)
			}
			base = strings.TrimPrefix(base, "$")
			if !strings.ContainsAny(base, "·/.") {
				base = "·" + base
			}
			address := wasmValue{typ: Ptr, val: llvmGlobal(resolve(base))}
			if offset != 0 {
				var err error
				address, err = addressPtr(address, offset)
				if err != nil {
					return err
				}
			}
			fmt.Fprintf(b, "  store %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
			return nil
		default:
			return fmt.Errorf("unsupported wasm destination operand %s", arg)
		}
	}
	emitReturn := func() error {
		if goABI {
			sp, err := loadRegister(SP)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", name, sp.val, fn.FrameSize+8)
			if _, err := storeRegister(SP, wasmValue{typ: I32, val: "%" + name}); err != nil {
				return err
			}
			b.WriteString("  ret i32 0\n")
			blockTerminated = true
			return nil
		}
		if len(results) > 1 {
			return errors.New("multiple FP result slots are unsupported by the direct WebAssembly ABI")
		}
		if sig.Ret == Void {
			b.WriteString("  ret void\n")
			blockTerminated = true
			return nil
		}
		if len(results) == 1 && haveResult[0] {
			if results[0].typ != sig.Ret {
				return fmt.Errorf("return type %s does not match stored result %s", sig.Ret, results[0].typ)
			}
			fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, results[0].val)
			blockTerminated = true
			return nil
		}
		if len(stack) != 0 {
			v := stack[len(stack)-1]
			if !v.stackAddr && v.typ == sig.Ret {
				fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, v.val)
				blockTerminated = true
				return nil
			}
		}
		return fmt.Errorf("missing %s return value", sig.Ret)
	}
	emitRawReturn := func() error {
		if physicalRet == Void {
			b.WriteString("  ret void\n")
			blockTerminated = true
			return nil
		}
		v, err := pop("Return")
		if err != nil {
			return err
		}
		want := wasmPhysicalStackType(physicalRet)
		if v.stackAddr || wasmPhysicalStackType(v.typ) != want {
			return fmt.Errorf("Return expects a %s stack value, got %s", want, v.typ)
		}
		v, err = cast(v, physicalRet, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "  ret %s %s\n", physicalRet, v.val)
		blockTerminated = true
		return nil
	}
	emitUnwindReturn := func() error {
		if !goABI {
			return fmt.Errorf("RETUNWIND requires the Go WebAssembly ABI")
		}
		sp, err := loadRegister(SP)
		if err != nil {
			return err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", name, sp.val, fn.FrameSize+8)
		if _, err := storeRegister(SP, wasmValue{typ: I32, val: "%" + name}); err != nil {
			return err
		}
		b.WriteString("  ret i32 1\n")
		blockTerminated = true
		return nil
	}
	emitTailCall := func(arg Operand) error {
		if goABI && arg.Kind == OpInvalid {
			target, err := pop("JMP")
			if err != nil {
				return err
			}
			target, err = cast(target, I64, false)
			if err != nil {
				return err
			}
			pcFunc := newTmp()
			fmt.Fprintf(b, "  %%%s = lshr i64 %s, 16\n", pcFunc, target.val)
			target32, err := cast(wasmValue{typ: I64, val: "%" + pcFunc}, I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target32, Ptr, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = tail call i32 %s(i32 0)\n", name, targetPtr.val)
			fmt.Fprintf(b, "  ret i32 %%%s\n", name)
			blockTerminated = true
			return nil
		}
		if arg.Kind != OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
			return fmt.Errorf("JMP expects a direct (SB) symbol")
		}
		callee := resolve(strings.TrimSuffix(arg.Sym, "(SB)"))
		calleeSig, ok := sigs[callee]
		if !ok {
			return fmt.Errorf("missing signature for tail target %q", callee)
		}
		if goABI {
			if calleeSig.WASMNative {
				return fmt.Errorf("Go ABI tail target %q uses a native WebAssembly signature", callee)
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = tail call i32 %s(i32 0)\n", name, llvmGlobal(funcSigSymbol(callee, calleeSig)))
			fmt.Fprintf(b, "  ret i32 %%%s\n", name)
			blockTerminated = true
			return nil
		}
		if len(calleeSig.Args) != len(sig.Args) {
			return fmt.Errorf("tail target %q needs %d arguments, caller has %d", callee, len(calleeSig.Args), len(sig.Args))
		}
		for i := range sig.Args {
			if sig.Args[i] != calleeSig.Args[i] {
				return fmt.Errorf("tail target %q argument %d has type %s, caller has %s", callee, i, calleeSig.Args[i], sig.Args[i])
			}
		}
		if sig.Ret != calleeSig.Ret {
			return fmt.Errorf("tail target %q returns %s, caller returns %s", callee, calleeSig.Ret, sig.Ret)
		}
		var args strings.Builder
		if calleeSig.WASMContext != "" {
			context, err := loadRegister(Reg("CTXT"))
			if err != nil {
				return fmt.Errorf("tail target %q context: %w", callee, err)
			}
			context, err = cast(context, calleeSig.WASMContext, false)
			if err != nil {
				return fmt.Errorf("tail target %q context: %w", callee, err)
			}
			fmt.Fprintf(&args, "%s %s", context.typ, context.val)
		}
		for i, typ := range calleeSig.Args {
			if args.Len() != 0 {
				args.WriteString(", ")
			}
			fmt.Fprintf(&args, "%s %%arg%d", typ, i)
		}
		if calleeSig.Ret == Void {
			fmt.Fprintf(b, "  tail call void %s(%s)\n  ret void\n", llvmGlobal(funcSigSymbol(callee, calleeSig)), args.String())
		} else {
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = tail call %s %s(%s)\n", name, calleeSig.Ret, llvmGlobal(funcSigSymbol(callee, calleeSig)), args.String())
			fmt.Fprintf(b, "  ret %s %%%s\n", calleeSig.Ret, name)
		}
		blockTerminated = true
		return nil
	}
	emitLocalCall := func(arg Operand) error {
		if arg.Kind != OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
			return fmt.Errorf("Call expects a direct (SB) symbol")
		}
		if !useGoStack && !strings.HasSuffix(arg.Sym, "<>(SB)") {
			return fmt.Errorf("Call currently supports file-local wasm helpers only")
		}
		callee := resolve(strings.TrimSuffix(arg.Sym, "(SB)"))
		calleeSig, ok := sigs[callee]
		if !ok {
			return fmt.Errorf("missing signature for local call target %q", callee)
		}
		argTypes := calleeSig.Args
		retType := calleeSig.Ret
		if useGoStack && !calleeSig.WASMNative {
			argTypes = []LLVMType{I32}
			retType = I32
		}
		if len(stack) < len(argTypes) {
			return fmt.Errorf("local call %q needs %d stack arguments, have %d", callee, len(argTypes), len(stack))
		}
		args := make([]wasmValue, len(argTypes))
		for i := len(args) - 1; i >= 0; i-- {
			v, _ := pop("Call") // len(stack) was checked above.
			var err error
			v, err = cast(v, argTypes[i], false)
			if err != nil {
				return fmt.Errorf("local call %q argument %d: %w", callee, i, err)
			}
			args[i] = v
		}
		var argText strings.Builder
		if !useGoStack && calleeSig.WASMContext != "" {
			context, err := loadRegister(Reg("CTXT"))
			if err != nil {
				return fmt.Errorf("local call %q context: %w", callee, err)
			}
			context, err = cast(context, calleeSig.WASMContext, false)
			if err != nil {
				return fmt.Errorf("local call %q context: %w", callee, err)
			}
			fmt.Fprintf(&argText, "%s %s", context.typ, context.val)
		}
		for _, v := range args {
			if argText.Len() != 0 {
				argText.WriteString(", ")
			}
			fmt.Fprintf(&argText, "%s %s", v.typ, v.val)
		}
		if retType == Void {
			fmt.Fprintf(b, "  call void %s(%s)\n", llvmGlobal(funcSigSymbol(callee, calleeSig)), argText.String())
			return nil
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = call %s %s(%s)\n", name, retType, llvmGlobal(funcSigSymbol(callee, calleeSig)), argText.String())
		push(wasmValue{typ: retType, val: "%" + name})
		return nil
	}
	emitGoCall := func(arg Operand, call wasmGoCallPC, continueLabel string) error {
		if !useGoStack {
			return fmt.Errorf("Go ABI CALL requires the Go WebAssembly ABI")
		}
		callee := ""
		calleeSig := FuncSig{}
		callTarget := ""
		if arg.Kind == OpInvalid {
			target, err := pop("CALL")
			if err != nil {
				return err
			}
			target, err = cast(target, I64, false)
			if err != nil {
				return err
			}
			pcFunc := newTmp()
			fmt.Fprintf(b, "  %%%s = lshr i64 %s, 16\n", pcFunc, target.val)
			target32, err := cast(wasmValue{typ: I64, val: "%" + pcFunc}, I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target32, Ptr, false)
			if err != nil {
				return err
			}
			callTarget = targetPtr.val
		} else {
			if arg.Kind != OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
				return fmt.Errorf("Go ABI CALL expects a direct (SB) symbol or an operand-stack target")
			}
			callee = resolve(strings.TrimSuffix(arg.Sym, "(SB)"))
			var ok bool
			calleeSig, ok = sigs[callee]
			if !ok {
				return fmt.Errorf("missing signature for Go ABI call target %q", callee)
			}
			if calleeSig.WASMNative {
				return fmt.Errorf("Go ABI CALL target %q uses a native WebAssembly signature", callee)
			}
			callTarget = llvmGlobal(funcSigSymbol(callee, calleeSig))
		}
		if len(stack) != 0 {
			return fmt.Errorf("Go ABI CALL requires an otherwise empty WebAssembly operand stack")
		}

		sp, err := loadRegister(SP)
		if err != nil {
			return err
		}
		callerSP := newTmp()
		fmt.Fprintf(b, "  %%%s = sub i32 %s, 8\n", callerSP, sp.val)
		if _, err := storeRegister(SP, wasmValue{typ: I32, val: "%" + callerSP}); err != nil {
			return err
		}
		callerAddr, err := cast(wasmValue{typ: I32, val: "%" + callerSP}, Ptr, false)
		if err != nil {
			return err
		}
		pcFunc := newTmp()
		fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to i64\n", pcFunc, llvmGlobal(sig.Name))
		pcBase := newTmp()
		fmt.Fprintf(b, "  %%%s = shl i64 %%%s, 16\n", pcBase, pcFunc)
		pc := "%" + pcBase
		if call.returnPC != 0 {
			pcValue := newTmp()
			fmt.Fprintf(b, "  %%%s = or i64 %%%s, %d\n", pcValue, pcBase, call.returnPC)
			pc = "%" + pcValue
		}
		fmt.Fprintf(b, "  store i64 %s, ptr %s, align 1\n", pc, callerAddr.val)
		unwind := newTmp()
		fmt.Fprintf(b, "  %%%s = call i32 %s(i32 0)\n", unwind, callTarget)
		isUnwind := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp ne i32 %%%s, 0\n", isUnwind, unwind)
		unwindLabel := "wasm_call_unwind_" + newTmp()
		if continueLabel == "" {
			continueLabel = "wasm_call_continue_" + newTmp()
		}
		fmt.Fprintf(b, "  br i1 %%%s, label %%%s, label %%%s\n%s:\n", isUnwind, unwindLabel, continueLabel, unwindLabel)
		if call.propagateUnwind && goABI {
			b.WriteString("  ret i32 1\n")
		} else {
			emitWASMTrap(b)
		}
		fmt.Fprintf(b, "%s:\n", continueLabel)
		blockTerminated = false
		return nil
	}
	emitIntCompare := func(op string, spec wasmIntegerComparisonOp) error {
		operands := [2]wasmValue{{}, {typ: spec.typ, val: "0"}}
		for index := spec.arity - 1; index >= 0; index-- {
			value, err := pop(op)
			if err != nil {
				return err
			}
			if value.typ != spec.typ || value.stackAddr {
				return fmt.Errorf("%s operand %d requires a %s stack value, got %s", op, index+1, spec.typ, value.typ)
			}
			operands[index] = value
		}
		cmp := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp %s %s %s, %s\n", cmp, spec.predicate, spec.typ, operands[0].val, operands[1].val)
		out := newTmp()
		fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
		push(wasmValue{typ: I32, val: "%" + out})
		return nil
	}
	addressPtr = func(v wasmValue, offset int64) (wasmValue, error) {
		var err error
		v, err = cast(v, Ptr, false)
		if err != nil {
			return wasmValue{}, err
		}
		if offset == 0 {
			return v, nil
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", name, v.val, offset)
		return wasmValue{typ: Ptr, val: "%" + name}, nil
	}
	root := &wasmControlFrame{
		wasmControlLabel: wasmControlLabel{kind: "function"},
		endLabel:         "wasm_function_return",
	}
	if physicalRet != Void {
		root.resultType = physicalRet
		root.resultSlot = "wasm_function_result"
		fmt.Fprintf(b, "  %%%s = alloca %s\n", root.resultSlot, root.resultType)
	}
	var (
		controls       = []*wasmControlFrame{root}
		deadControls   wasmDeadControls
		pendingName    string
		rootBranchUsed bool
	)
	copyStack := func(values []wasmValue) []wasmValue {
		return append([]wasmValue(nil), values...)
	}
	newLabel := func(prefix string) string {
		return prefix + "_" + newTmp()
	}
	memoryAddress := func(op string, form wasmMemoryForm) (wasmValue, error) {
		var base wasmValue
		var err error
		width := form.spec.guardedWidth()
		if form.base != "" {
			base, err = loadRegister(form.base)
		} else {
			base, err = pop(op)
		}
		if err != nil {
			return wasmValue{}, err
		}
		if form.base != "" && base.typ == I64 {
			base, err = cast(base, I32, false)
			if err != nil {
				return wasmValue{}, err
			}
		}
		if base.typ == Ptr && !base.stackAddr {
			if width == 0 {
				// A direct ABI caller can supply a typed host pointer.
				return addressPtr(base, form.offset)
			}
			base, err = cast(base, I32, false)
			if err != nil {
				return wasmValue{}, err
			}
		}
		if base.typ != I32 || base.stackAddr {
			return wasmValue{}, fmt.Errorf("%s expects an i32 linear-memory address, got %s", op, base.typ)
		}
		if width != 0 {
			emitWASMVectorMemoryBounds(b, base.val, form.offset+width, newTmp, newLabel)
			return addressPtr(base, form.offset)
		}
		if form.offset != 0 {
			// Wasm adds the unsigned offset without wrapping. Native memory
			// instructions still check the end of the access against memory.
			valid, effective := newTmp(), newTmp()
			fmt.Fprintf(b, "  %%%s = icmp ule i32 %s, %d\n", valid, base.val, math.MaxUint32-form.offset)
			emitWASMTrapUnless(b, valid, newLabel)
			fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", effective, base.val, form.offset)
			base.val = "%" + effective
		}
		return cast(base, Ptr, false)
	}
	emitMemory := func(op string, ins Instr, form wasmMemoryForm) error {
		spec := form.spec
		var input wasmValue
		if spec.consumesValue() {
			var err error
			input, err = pop(op)
			if err != nil {
				return err
			}
			if input.typ != spec.stack || input.stackAddr {
				return fmt.Errorf("%s expects a %s stack value, got %s", op, spec.stack, input.typ)
			}
		}
		if spec.store {
			value := input
			var err error
			if spec.vector != nil {
				value = emitWASMVectorMemoryStoreLane(b, newTmp, form, input)
			} else {
				value, err = cast(input, spec.access, false)
			}
			if err != nil {
				return err
			}
			if form.frame {
				if len(stack) != 0 && stack[len(stack)-1].stackAddr {
					stack = stack[:len(stack)-1]
				}
				return storeResult(ins.Args[len(ins.Args)-1], value)
			}
			address, err := memoryAddress(op, form)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  store volatile %s %s, ptr %s, align 1\n", spec.access, value.val, address.val)
			return nil
		}
		var value wasmValue
		if form.frame {
			var err error
			value, err = loadOperand(ins.Args[0], spec.access)
			if err != nil {
				return err
			}
		} else {
			address, err := memoryAddress(op, form)
			if err != nil {
				return err
			}
			name := newTmp()
			// A discarded result still observes the original memory trap.
			fmt.Fprintf(b, "  %%%s = load volatile %s, ptr %s, align 1\n", name, spec.access, address.val)
			value = wasmValue{typ: spec.access, val: "%" + name}
		}
		if spec.vector != nil {
			push(emitWASMVectorMemoryLoad(b, newTmp, form, value, input))
			return nil
		}
		value, err := cast(value, spec.stack, spec.signed)
		if err != nil {
			return err
		}
		push(value)
		return nil
	}
	emitLabel := func(label string) {
		fmt.Fprintf(b, "%s:\n", label)
		blockTerminated = false
	}
	conditionValue := func(op string) (string, error) {
		condition, err := pop(op)
		if err != nil {
			return "", err
		}
		if condition.stackAddr {
			return "", fmt.Errorf("%s condition requires i32, got a stack-address marker", op)
		}
		if condition.typ != I32 {
			return "", fmt.Errorf("%s condition requires i32, got %s", op, condition.typ)
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp ne i32 %s, 0\n", name, condition.val)
		return "%" + name, nil
	}
	emitMemoryBuiltin := func(op string, spec wasmMemoryBuiltin) error {
		var operands [3]wasmValue
		for index := len(spec.operands) - 1; index >= 0; index-- {
			value, err := pop(op)
			if err != nil {
				return err
			}
			role := spec.operands[index]
			if value.stackAddr {
				return fmt.Errorf("%s %s requires an i32 stack value, got a stack-address marker", op, role)
			}
			if value.typ != I32 {
				return fmt.Errorf("%s %s requires an i32 stack value, got %s", op, role, value.typ)
			}
			operands[index] = value
		}
		if !spec.isBulk() {
			args := "i32 0"
			if len(spec.operands) != 0 {
				args += ", i32 " + operands[0].val
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.%s.i32(%s)\n", name, spec.intrinsic, args)
			push(wasmValue{typ: I32, val: "%" + name})
			return nil
		}

		dst, src, length := operands[0], operands[1], operands[2]
		dstPtr, err := cast(dst, Ptr, false)
		if err != nil {
			return err
		}
		source, err := cast(src, spec.sourceAccess, false)
		if err != nil {
			return err
		}
		if spec.sourceAccess == Ptr {
			emitWASMBulkMemoryBounds(b, length.val, newTmp, newLabel, dst.val, src.val)
			fmt.Fprintf(b, "  call void @llvm.memmove.p0.p0.i32(ptr %s, ptr %s, i32 %s, i1 false)\n", dstPtr.val, source.val, length.val)
		} else {
			emitWASMBulkMemoryBounds(b, length.val, newTmp, newLabel, dst.val)
			fmt.Fprintf(b, "  call void @llvm.memset.p0.i32(ptr %s, i8 %s, i32 %s, i1 false)\n", dstPtr.val, source.val, length.val)
		}
		return nil
	}
	storeBlockResult := func(frame *wasmControlFrame, stackBase int, popValue bool) error {
		if frame.resultType == "" {
			return nil
		}
		if len(stack) <= stackBase {
			return fmt.Errorf("%s block is missing its %s result", frame.kind, frame.resultType)
		}
		v := stack[len(stack)-1]
		want, got := frame.resultType, v.typ
		if frame.kind == "function" {
			want, got = wasmPhysicalStackType(want), wasmPhysicalStackType(got)
		}
		if v.stackAddr || got != want {
			return fmt.Errorf("%s block result requires %s, got %s", frame.kind, want, v.typ)
		}
		if popValue {
			stack = stack[:len(stack)-1]
		}
		var err error
		v, err = cast(v, frame.resultType, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "  store %s %s, ptr %%%s\n", frame.resultType, v.val, frame.resultSlot)
		return nil
	}
	finishControlPath := func(frame *wasmControlFrame) error {
		if blockTerminated {
			return nil
		}
		if err := storeBlockResult(frame, len(frame.baseStack), true); err != nil {
			return err
		}
		fmt.Fprintf(b, "  br label %%%s\n", frame.endLabel)
		blockTerminated = true
		return nil
	}
	emitBranch := func(ins Instr, op string) error {
		targetIndex, err := wasmBranchTarget(ins, op, len(controls), func(i int) string {
			return controls[i].name
		})
		if err != nil {
			return err
		}
		target := controls[targetIndex]
		conditional := op == "BRIF"
		stackBase := len(controls[len(controls)-1].baseStack)
		var condition string
		if conditional {
			if len(stack) <= stackBase {
				return fmt.Errorf("%s operand stack underflow", op)
			}
			condition, err = conditionValue(op)
			if err != nil {
				return err
			}
		}
		if target.branchResult() != "" {
			// An outer label's result still has to come from the current
			// block's operand stack, above its entry height.
			if err := storeBlockResult(target, stackBase, !conditional); err != nil {
				return err
			}
		}
		if target.kind == "function" {
			rootBranchUsed = true
		}
		label := target.endLabel
		if target.kind == "loop" {
			label = target.startLabel
		}
		if conditional {
			continuation := newLabel("wasm_br_cont")
			fmt.Fprintf(b, "  br i1 %s, label %%%s, label %%%s\n", condition, label, continuation)
			emitLabel(continuation)
			return nil
		}
		fmt.Fprintf(b, "  br label %%%s\n", label)
		blockTerminated = true
		return nil
	}

	var goABIOuter *strings.Builder
	if goABI {
		// Build the function body separately so the entry dispatch can contain
		// only resume labels that were actually emitted. A terminating tail
		// return can make a later lexical CALL unreachable.
		goABIOuter = b
		b = &strings.Builder{}
		b.WriteString("wasm_entry_body:\n")
		if fn.FrameSize != 0 {
			sp, err := loadRegister(SP)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = sub i32 %s, %d\n", name, sp.val, fn.FrameSize)
			if _, err := storeRegister(SP, wasmValue{typ: I32, val: "%" + name}); err != nil {
				return err
			}
		}
	}

	for insIndex, ins := range fn.Instrs {
		op := normalizeInstructionOpcode(ins.Op)
		if op == "TEXT" {
			continue
		}
		if annotateSource && ins.Raw != "" {
			fmt.Fprintf(b, "  ; %s\n", strings.ReplaceAll(ins.Raw, "\n", " "))
		}
		if blockTerminated {
			skip, err := deadControls.skip(op, controlResults[insIndex])
			if err != nil {
				return err
			}
			if skip {
				if goABI && resumePlan != nil && op == "CALL" && len(deadControls) == 0 {
					// The skipped call can still be followed by an independently
					// reachable continuation in the original dispatcher.
					stack = nil
					emitLabel(wasmResumeLabel(resumePlan.entries[insIndex]))
				}
				continue
			}
		}
		if spec, ok := wasmsimd.Lookup(op); ok {
			var inputs [3]wasmValue
			for index := spec.Arity() - 1; index >= 0; index-- {
				value, err := pop(op)
				if err != nil {
					return err
				}
				want := LLVMType(spec.InputType(index))
				if value.typ != want || value.stackAddr {
					return fmt.Errorf("%s operand %d requires stack value %s, got %s", ins.Op, index+1, want, value.typ)
				}
				inputs[index] = value
			}
			push(emitWASMV128Core(b, newTmp, spec, ins, inputs[:spec.Arity()]))
			continue
		}
		if spec, ok := wasmIntegerCountOps[op]; ok {
			value, err := pop(op)
			if err != nil {
				return err
			}
			if value.typ != spec.typ || value.stackAddr {
				return fmt.Errorf("%s expects one %s stack value, got %s", ins.Op, spec.typ, value.typ)
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call %s @llvm.%s.%s(%s %s", name, spec.typ, spec.intrinsic, spec.typ, spec.typ, value.val)
			if spec.intrinsic != "ctpop" {
				b.WriteString(", i1 false") // Zero is defined, never LLVM poison.
			}
			b.WriteString(")\n")
			push(wasmValue{typ: spec.typ, val: "%" + name})
			continue
		}
		if spec, ok := wasmConversionOps[op]; ok {
			value, err := pop(op)
			if err != nil {
				return err
			}
			if value.stackAddr {
				return fmt.Errorf("%s cannot convert a stack-address marker", ins.Op)
			}
			if value.typ != spec.source {
				return fmt.Errorf("%s expects one %s stack value, got %s", ins.Op, spec.source, value.typ)
			}
			push(spec.emit(b, value, newTmp, newLabel))
			continue
		}
		if spec, ok := wasmIntegerBinaryOps[op]; ok {
			right, err := pop(op)
			if err != nil {
				return err
			}
			left, err := pop(op)
			if err != nil {
				return err
			}
			if left.typ != spec.typ || right.typ != spec.typ || left.stackAddr || right.stackAddr {
				return fmt.Errorf("%s expects two %s stack values, got %s and %s", ins.Op, spec.typ, left.typ, right.typ)
			}
			push(spec.emitBinary(b, left, right, newTmp, newLabel))
			continue
		}
		if spec, ok := wasmIntegerCompareOps[op]; ok {
			if err := emitIntCompare(op, spec); err != nil {
				return err
			}
			continue
		}
		if spec, ok := wasmFloatBinaryProperties(op); ok {
			rhs, err := pop(op)
			if err != nil {
				return err
			}
			lhs, err := pop(op)
			if err != nil {
				return err
			}
			if lhs.typ != spec.typ || rhs.typ != spec.typ || lhs.stackAddr || rhs.stackAddr {
				return fmt.Errorf("%s expects two %s stack values, got %s and %s", ins.Op, spec.typ, lhs.typ, rhs.typ)
			}
			name := newTmp()
			if spec.predicate != "" {
				fmt.Fprintf(b, "  %%%s = fcmp %s %s %s, %s\n", name, spec.predicate, spec.typ, lhs.val, rhs.val)
				result := newTmp()
				fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", result, name)
				name = result
			} else {
				bits := 32
				if spec.typ == "double" {
					bits = 64
				}
				if spec.operation != "" {
					// No fast-math flags: signed zero, infinities, gradual
					// underflow and the declared rounding precision are live.
					fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", name, spec.operation, spec.typ, lhs.val, rhs.val)
				} else {
					fmt.Fprintf(b, "  %%%s = call %s @llvm.%s.f%d(%s %s, %s %s)\n", name, spec.typ, spec.intrinsic, bits, spec.typ, lhs.val, spec.typ, rhs.val)
				}
				if spec.intrinsic == "copysign" {
					// CopySign changes only the sign bit, including on NaNs.
					push(wasmValue{typ: spec.typ, val: "%" + name})
					continue
				}
				// LLVM may fold minimum(x,x) or identity arithmetic to x,
				// including a signaling NaN. Wasm requires a quiet NaN;
				// canonical NaN is valid for every permitted input payload.
				// Integer bits keep optimization from discarding quieting as
				// a redundant floating-point operation.
				signless, infinity, canonical := wasmFloatNaNBits(bits)
				raw, magnitude, isNaN, selected, normalized := newTmp(), newTmp(), newTmp(), newTmp(), newTmp()
				fmt.Fprintf(b, "  %%%s = bitcast %s %%%s to i%d\n", raw, spec.typ, name, bits)
				fmt.Fprintf(b, "  %%%s = and i%d %%%s, %d\n", magnitude, bits, raw, signless)
				fmt.Fprintf(b, "  %%%s = icmp ugt i%d %%%s, %d\n", isNaN, bits, magnitude, infinity)
				fmt.Fprintf(b, "  %%%s = select i1 %%%s, i%d %d, i%d %%%s\n", selected, isNaN, bits, canonical, bits, raw)
				fmt.Fprintf(b, "  %%%s = bitcast i%d %%%s to %s\n", normalized, bits, selected, spec.typ)
				name = normalized
			}
			push(wasmValue{typ: spec.resultType(), val: "%" + name})
			continue
		}
		if spec, ok := wasmFloatUnaryOps[op]; ok {
			if len(ins.Args) != 0 {
				return fmt.Errorf("%s is a zero-operand WebAssembly stack instruction", ins.Op)
			}
			value, err := pop(op)
			if err != nil {
				return err
			}
			if value.typ != spec.typ || value.stackAddr {
				wantType := "f32"
				if spec.typ == LLVMType("double") {
					wantType = "f64"
				}
				return fmt.Errorf("%s expects %s, got %s", op, wantType, value.typ)
			}
			name := newTmp()
			if spec.intrinsic == "" {
				fmt.Fprintf(b, "  %%%s = fneg %s %s\n", name, spec.typ, value.val)
			} else {
				bits := "32"
				if spec.typ == LLVMType("double") {
					bits = "64"
				}
				fmt.Fprintf(b, "  %%%s = call %s @llvm.%s.f%s(%s %s)\n", name, spec.typ, spec.intrinsic, bits, spec.typ, value.val)
			}
			push(wasmValue{typ: spec.typ, val: "%" + name})
			continue
		}
		if form, ok := memoryForms[insIndex]; ok {
			if err := emitMemory(op, ins, form); err != nil {
				return err
			}
			continue
		}
		if spec, ok := wasmMemoryBuiltins[op]; ok {
			if err := emitMemoryBuiltin(op, spec); err != nil {
				return err
			}
			continue
		}
		switch op {
		case "NOP", "NO_LOCAL_POINTERS", "FUNCDATA", "PCDATA":
			continue
		case "RESUMEPOINT":
			label := wasmResumeLabel(resumePlan.entries[insIndex])
			if blockTerminated {
				stack = nil
			} else {
				if len(stack) != 0 {
					return fmt.Errorf("RESUMEPOINT requires an empty WebAssembly operand stack")
				}
				fmt.Fprintf(b, "  br label %%%s\n", label)
			}
			emitLabel(label)
		case "LABEL":
			if len(ins.Args) != 1 {
				return fmt.Errorf("wasm label expects one name")
			}
			pendingName = strings.TrimSuffix(ins.Args[0].Sym, ":")
		case "BLOCK", "LOOP", "IF":
			frame := &wasmControlFrame{
				wasmControlLabel: wasmControlLabel{
					kind:       strings.ToLower(op),
					name:       pendingName,
					resultType: controlResults[insIndex],
				},
				endLabel:  newLabel("wasm_control_end"),
				baseStack: copyStack(stack),
			}
			pendingName = ""
			if frame.resultType != "" {
				frame.resultSlot = wasmControlResultSlot(insIndex)
			}
			switch op {
			case "LOOP":
				frame.startLabel = newLabel("wasm_loop")
				fmt.Fprintf(b, "  br label %%%s\n", frame.startLabel)
				emitLabel(frame.startLabel)
			case "IF":
				condition, err := conditionValue(op)
				if err != nil {
					return err
				}
				frame.baseStack = copyStack(stack)
				thenLabel := newLabel("wasm_if_then")
				frame.elseLabel = newLabel("wasm_if_else")
				fmt.Fprintf(b, "  br i1 %s, label %%%s, label %%%s\n", condition, thenLabel, frame.elseLabel)
				emitLabel(thenLabel)
			}
			controls = append(controls, frame)
		case "ELSE":
			if len(controls) == 0 || controls[len(controls)-1].kind != "if" {
				return fmt.Errorf("Else without matching If")
			}
			frame := controls[len(controls)-1]
			if frame.inElse {
				return fmt.Errorf("duplicate Else")
			}
			if err := finishControlPath(frame); err != nil {
				return err
			}
			stack = copyStack(frame.baseStack)
			emitLabel(frame.elseLabel)
			frame.inElse = true
		case "END":
			if len(controls) <= 1 {
				return fmt.Errorf("End without active control")
			}
			frame := controls[len(controls)-1]
			controls = controls[:len(controls)-1]
			if frame.kind == "if" && !frame.inElse {
				if err := finishControlPath(frame); err != nil {
					return err
				}
				stack = copyStack(frame.baseStack)
				emitLabel(frame.elseLabel)
				if frame.resultType != "" {
					return fmt.Errorf("result-producing If requires Else")
				}
			}
			if err := finishControlPath(frame); err != nil {
				return err
			}
			stack = copyStack(frame.baseStack)
			emitLabel(frame.endLabel)
			if frame.resultType != "" {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = load %s, ptr %%%s\n", name, frame.resultType, frame.resultSlot)
				push(wasmValue{typ: frame.resultType, val: "%" + name})
			}
		case "BR", "BRIF":
			if err := emitBranch(ins, op); err != nil {
				return err
			}
		case "GET":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
				return fmt.Errorf("Get expects one register")
			}
			if ins.Args[0].Reg == SP {
				if useGoStack {
					v, err := loadRegister(SP)
					if err != nil {
						return err
					}
					push(v)
				} else {
					push(wasmValue{typ: I32, val: "0", stackAddr: true})
				}
				continue
			}
			v, err := loadRegister(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			push(v)
		case "SET", "TEE":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
				return fmt.Errorf("%s expects one register", ins.Op)
			}
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = storeRegister(ins.Args[0].Reg, v)
			if err != nil {
				return err
			}
			if op == "TEE" {
				push(v)
			}
		case "MOVB", "MOVH", "MOVW", "MOVD":
			if len(ins.Args) != 2 {
				return fmt.Errorf("%s expects source and destination", ins.Op)
			}
			width := wasmMoveTypes[op]
			loadWidth := width
			if ins.Args[0].Kind == OpReg || ins.Args[0].Kind == OpImm || ins.Args[0].Kind == OpFPAddr ||
				ins.Args[0].Kind == OpSym && strings.HasPrefix(strings.TrimSpace(ins.Args[0].Sym), "$") {
				// Go MOV widths select memory access size. Register,
				// immediate and address values retain all 64 bits.
				loadWidth = I64
			}
			v, err := loadOperand(ins.Args[0], loadWidth)
			if err != nil {
				return err
			}
			if ins.Args[1].Kind != OpReg {
				v, err = cast(v, width, false)
				if err != nil {
					return err
				}
			}
			if ins.Args[1].Kind == OpSym && strings.HasPrefix(strings.TrimSpace(ins.Args[1].Sym), "$") {
				return fmt.Errorf("%s cannot store into an immediate symbol address", ins.Op)
			}
			if err := storeOperand(ins.Args[1], v); err != nil {
				return err
			}
		case "I32CONST", "I64CONST":
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one integer immediate", ins.Op)
			}
			typ := I32
			if op == "I64CONST" {
				typ = I64
			}
			if ins.Args[0].Kind == OpImm {
				push(wasmValue{typ: typ, val: fmt.Sprintf("%d", ins.Args[0].Imm)})
				continue
			}
			v, err := loadOperand(ins.Args[0], typ)
			if err != nil {
				return fmt.Errorf("%s expects one integer immediate or symbol address: %w", ins.Op, err)
			}
			push(v)
		case "F32CONST", "F64CONST":
			constant, _, err := parseWASMFloatConstant(ins, op)
			if err != nil {
				return err
			}
			push(constant.value())
		case "SELECT":
			condition, err := conditionValue(op)
			if err != nil {
				return err
			}
			ifFalse, err := pop(op)
			if err != nil {
				return err
			}
			ifTrue, err := pop(op)
			if err != nil {
				return err
			}
			if ifTrue.typ != ifFalse.typ {
				return fmt.Errorf("Select value type mismatch: %s and %s", ifTrue.typ, ifFalse.typ)
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = select i1 %s, %s %s, %s %s\n", name, condition, ifTrue.typ, ifTrue.val, ifFalse.typ, ifFalse.val)
			push(wasmValue{typ: ifTrue.typ, val: "%" + name})
		case "DROP":
			if _, err := pop(op); err != nil {
				return err
			}
		case "RET":
			if len(ins.Args) == 1 {
				if err := emitTailCall(ins.Args[0]); err != nil {
					return err
				}
			} else if len(ins.Args) != 0 {
				return fmt.Errorf("RET expects at most one target")
			} else if err := emitReturn(); err != nil {
				return err
			}
		case "RETUNWIND":
			if err := emitUnwindReturn(); err != nil {
				return err
			}
		case "WASMRETURN":
			if err := emitRawReturn(); err != nil {
				return err
			}
		case "JMP":
			if resumePlan != nil {
				if jump, ok := resumePlan.jumps[insIndex]; ok {
					if slot, found := regSlots[Reg("PC_B")]; found {
						fmt.Fprintf(b, "  store i32 %d, ptr %%%s\n", jump.pc, slot)
					}
					fmt.Fprintf(b, "  br label %%%s\n", wasmResumeLabel(jump.entry))
					blockTerminated = true
					continue
				}
			}
			if len(ins.Args) > 1 || len(ins.Args) == 0 && !goABI {
				return fmt.Errorf("JMP expects one target")
			}
			target := Operand{}
			if len(ins.Args) == 1 {
				target = ins.Args[0]
			}
			if err := emitTailCall(target); err != nil {
				return err
			}
		case "CALL", "CALLNORESUME":
			if len(ins.Args) > 1 {
				return fmt.Errorf("%s expects at most one target", ins.Op)
			}
			target := Operand{}
			if len(ins.Args) == 1 {
				target = ins.Args[0]
			}
			if resumePlan == nil {
				return fmt.Errorf("%s requires the Go WebAssembly ABI", op)
			}
			// Only the Go ABI entry has a PC_B resume switch. Native helpers
			// still use the linear Go stack for calls, but continue directly
			// after a normally returning callee.
			resumeLabel := ""
			if op == "CALL" && goABI {
				resumeLabel = wasmResumeLabel(resumePlan.entries[insIndex])
			}
			if err := emitGoCall(target, resumePlan.calls[insIndex], resumeLabel); err != nil {
				return err
			}
		case "CALLINDIRECT":
			if !useGoStack {
				return fmt.Errorf("CallIndirect requires the Go WebAssembly ABI")
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm != 0 {
				return fmt.Errorf("CallIndirect expects the Go function-table type $0")
			}
			target, err := pop(op)
			if err != nil {
				return err
			}
			pcB, err := pop(op)
			if err != nil {
				return err
			}
			target, err = cast(target, I32, false)
			if err != nil {
				return err
			}
			pcB, err = cast(pcB, I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target, Ptr, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 %s(i32 %s)\n", name, targetPtr.val, pcB.val)
			push(wasmValue{typ: I32, val: "%" + name})
		case "CALLIMPORT":
			if !useGoStack {
				return fmt.Errorf("CallImport requires the Go WebAssembly ABI")
			}
			sp, err := loadRegister(SP)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  call void %s(i32 %s)\n", llvmGlobal(resolve(fn.Sym)+"$wasmimport"), sp.val)
		case "WASMCALL":
			if len(ins.Args) != 1 {
				return fmt.Errorf("Call expects one target")
			}
			if err := emitLocalCall(ins.Args[0]); err != nil {
				return err
			}
		case "UNDEF", "UNREACHABLE":
			emitWASMTrap(b)
			blockTerminated = true
		default:
			return fmt.Errorf("unsupported wasm instruction %s", ins.Op)
		}
	}
	if open := len(controls) - 1 + len(deadControls); open != 0 {
		return fmt.Errorf("%d unterminated wasm control blocks", open)
	}
	if !blockTerminated {
		if goABI {
			// cmd/asm appends UNDEF after the original Go function body.
			emitWASMTrap(b)
		} else if useGoStack && sig.WASMNative && physicalRet != Void {
			// Native helpers such as gcWriteBarrier end in an infinite Loop.
			// Structured lowering still materializes the unreachable loop-exit
			// label; terminate that synthetic path without inventing a value.
			b.WriteString("  unreachable\n")
			blockTerminated = true
		} else if err := emitReturn(); err != nil {
			return err
		}
	}
	if rootBranchUsed {
		emitLabel(root.endLabel)
		if root.resultType == "" {
			b.WriteString("  ret void\n")
		} else {
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = load %s, ptr %%%s\n", name, root.resultType, root.resultSlot)
			fmt.Fprintf(b, "  ret %s %%%s\n", root.resultType, name)
		}
	}
	b.WriteString("}\n")
	if goABI {
		body := b.String()
		b = goABIOuter
		if resumePlan != nil {
			resumePlan.emitDispatch(b)
		} else {
			b.WriteString("  br label %wasm_entry_body\n")
		}
		b.WriteString(body)
	}
	return nil
}

// wasmNeedsIncomingContext reports whether fn reads CTXT before establishing a
// new value itself. LLGo transports this compiler-owned closure environment as
// an explicit physical parameter on WebAssembly; it is intentionally separate
// from the Go signature represented by FuncSig.Args.
func wasmNeedsIncomingContext(fn Func) bool {
	initialized := false
	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		_, move := wasmMoveTypes[op]
		memory, _ := lookupWASMMemoryOp(op)
		for i, arg := range ins.Args {
			if memory.store && arg.Kind == OpMem {
				continue
			}
			writes := (op == "SET" || op == "TEE") && i == 0 && arg.Kind == OpReg ||
				move && i == 1 && arg.Kind == OpReg
			if writes && arg.Reg == Reg("CTXT") {
				initialized = true
				continue
			}
			if (arg.Kind == OpReg && arg.Reg == Reg("CTXT")) ||
				(arg.Kind == OpMem && arg.Mem.Base == Reg("CTXT")) {
				if !initialized {
					return true
				}
			}
		}
	}
	return false
}

func wasmGoGlobalRegister(reg Reg) bool {
	name := strings.ToUpper(string(reg))
	return name == "SP" || name == "CTXT" || name == "G" || name == "PAUSE" ||
		strings.HasPrefix(name, "RET")
}

func wasmGoGlobalName(reg Reg) string {
	if strings.EqualFold(string(reg), "g") {
		return "g"
	}
	return strings.ToUpper(string(reg))
}
