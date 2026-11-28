package wasm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type wasmValue struct {
	typ       asm.LLVMType
	val       string
	stackAddr bool
}

// A direct-ABI result slot can be written on every path, no path, or some
// paths. The union at structured exits preserves that distinction.
type resultPaths uint8

const (
	resultUnset resultPaths = 1 << iota
	resultStored
)

type wasmControlFrame struct {
	kind                      string
	name                      string
	startLabel                string
	elseLabel                 string
	endLabel                  string
	baseStack                 []wasmValue
	resultType                asm.LLVMType
	resultSlot                string
	inElse                    bool
	entryResults, exitResults resultPaths
}

// translateFuncWASM lowers WebAssembly Plan 9 stack instructions into ordinary
// LLVM SSA. The direct ABI maps FP operands through FuncSig.Frame. The Go ABI
// instead recreates the official compiler's linear-memory stack, register
// globals, resumable calls, and unwind return protocol.
func TranslateFunc(b *strings.Builder, fn asm.Func, sig asm.FuncSig, resolve func(string) string, sigs map[string]asm.FuncSig, wasmABI asm.WASMABI, annotateSource bool) error {
	useGoStack := wasmABI == asm.WASMABIGo
	goABI := useGoStack && !sig.WASMNative
	physicalRet := sig.Ret
	if goABI {
		physicalRet = asm.I32
	}
	fmt.Fprintf(b, "define %s %s(", physicalRet, asm.LLVMGlobal(sig.Name))
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
	b.WriteString(" null_pointer_is_valid {\nentry:\n")

	var (
		stack           []wasmValue
		regSlots        = make(map[asm.Reg]string)
		regInitialized  = make(map[asm.Reg]bool)
		resultState     = resultUnset
		tmp             int
		blockTerminated bool
	)
	if !useGoStack && len(sig.Frame.Results) == 1 {
		fmt.Fprintf(b, "  %%wasm_fp_result = alloca %s\n", sig.Frame.Results[0].Type)
	}
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
	cast := func(v wasmValue, to asm.LLVMType, signed bool) (wasmValue, error) {
		if v.stackAddr {
			return wasmValue{}, fmt.Errorf("cannot cast stack-address marker to %s", to)
		}
		if v.typ == to {
			return v, nil
		}
		name := newTmp()
		switch {
		case isWasmV128(v.typ) && isWasmV128(to):
			fmt.Fprintf(b, "  %%%s = bitcast %s %s to %s\n", name, v.typ, v.val, to)
		case v.typ == asm.Ptr && (to == asm.I32 || to == asm.I64):
			fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to %s\n", name, v.val, to)
		case (v.typ == asm.I32 || v.typ == asm.I64) && to == asm.Ptr:
			fmt.Fprintf(b, "  %%%s = inttoptr %s %s to ptr\n", name, v.typ, v.val)
		case (v.typ == asm.I1 || v.typ == asm.I8 || v.typ == asm.I16 || v.typ == asm.I32) && to == asm.I64:
			op := "zext"
			if signed {
				op = "sext"
			}
			fmt.Fprintf(b, "  %%%s = %s %s %s to i64\n", name, op, v.typ, v.val)
		case (v.typ == asm.I1 || v.typ == asm.I8 || v.typ == asm.I16) && to == asm.I32:
			op := "zext"
			if signed {
				op = "sext"
			}
			fmt.Fprintf(b, "  %%%s = %s %s %s to i32\n", name, op, v.typ, v.val)
		case v.typ == asm.I64 && (to == asm.I32 || to == asm.I16 || to == asm.I8 || to == asm.I1):
			fmt.Fprintf(b, "  %%%s = trunc i64 %s to %s\n", name, v.val, to)
		case v.typ == asm.I32 && (to == asm.I16 || to == asm.I8 || to == asm.I1):
			fmt.Fprintf(b, "  %%%s = trunc i32 %s to %s\n", name, v.val, to)
		case v.typ == asm.I16 && (to == asm.I8 || to == asm.I1):
			fmt.Fprintf(b, "  %%%s = trunc i16 %s to %s\n", name, v.val, to)
		case v.typ == asm.I8 && to == asm.I1:
			fmt.Fprintf(b, "  %%%s = trunc i8 %s to i1\n", name, v.val)
		default:
			return wasmValue{}, fmt.Errorf("unsupported wasm cast %s to %s", v.typ, to)
		}
		return wasmValue{typ: to, val: "%" + name}, nil
	}
	wasmRType := asm.I64
	argRegTypes := make(map[asm.Reg]asm.LLVMType, len(sig.ArgRegs))
	for i, reg := range sig.ArgRegs {
		if i < len(sig.Args) {
			argRegTypes[reg] = sig.Args[i]
		}
		if i >= len(sig.Args) || !strings.HasPrefix(strings.ToUpper(string(reg)), "R") {
			continue
		}
		if sig.Args[i] == asm.I32 || sig.Args[i] == asm.I64 {
			wasmRType = sig.Args[i]
			break
		}
	}
	registerType := func(reg asm.Reg) (asm.LLVMType, error) {
		name := strings.ToUpper(string(reg))
		switch {
		case argRegTypes[reg] != "":
			return argRegTypes[reg], nil
		case useGoStack && name == "SP":
			return asm.I32, nil
		case useGoStack && (name == "CTXT" || name == "G" || strings.HasPrefix(name, "RET")):
			return asm.I64, nil
		case useGoStack && name == "PAUSE":
			return asm.I32, nil
		case name == "CTXT" && sig.WASMContext != "":
			return sig.WASMContext, nil
		case strings.HasPrefix(name, "R"), name == "CTXT", name == "G",
			strings.HasPrefix(name, "RET"), name == "PAUSE":
			return wasmRType, nil
		case name == "PC_B":
			return asm.I32, nil
		case strings.HasPrefix(name, "F"):
			n := 0
			if _, err := fmt.Sscanf(name, "F%d", &n); err != nil {
				return "", fmt.Errorf("invalid wasm register %s", reg)
			}
			if n < 16 {
				return asm.LLVMType("float"), nil
			}
			return asm.LLVMType("double"), nil
		case strings.HasPrefix(name, "V"):
			return asm.LLVMType("<4 x i32>"), nil
		default:
			return "", fmt.Errorf("unsupported wasm register %s", reg)
		}
	}
	for i, ins := range fn.Instrs {
		switch asm.NormalizeInstructionOpcode(ins.Op) {
		case "IF", "LOOP", "BLOCK":
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm {
				if typ := wasmBlockResultType(ins.Args[0].Imm); typ != "" {
					fmt.Fprintf(b, "  %%wasm_control_result_%d = alloca %s\n", i, typ)
				}
			}
		}
	}
	for _, ins := range fn.Instrs {
		for _, arg := range ins.Args {
			var reg asm.Reg
			switch arg.Kind {
			case asm.OpReg:
				reg = arg.Reg
			case asm.OpMem:
				reg = arg.Mem.Base
			default:
				continue
			}
			if reg == "" || reg == asm.SP || useGoStack && wasmGoGlobalRegister(reg) {
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
			fmt.Fprintf(b, "  store %s %s, ptr %%%s\n", typ, asm.LLVMZeroValue(typ), slot)
		}
	}
	for i, reg := range sig.ArgRegs {
		if goABI {
			break
		}
		if i >= len(sig.Args) || reg == asm.SP {
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
		if slot, ok := regSlots[asm.Reg("PC_B")]; ok {
			fmt.Fprintf(b, "  store i32 %%pc_b, ptr %%%s\n", slot)
			regInitialized[asm.Reg("PC_B")] = true
		}
	}
	if !useGoStack && sig.WASMContext != "" {
		if slot, ok := regSlots[asm.Reg("CTXT")]; ok {
			fmt.Fprintf(b, "  store %s %%wasm_context, ptr %%%s\n", sig.WASMContext, slot)
			regInitialized[asm.Reg("CTXT")] = true
		}
	}
	loadRegister := func(reg asm.Reg) (wasmValue, error) {
		if useGoStack && wasmGoGlobalRegister(reg) {
			typ, err := registerType(reg)
			if err != nil {
				return wasmValue{}, err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = load %s, ptr addrspace(1) %s\n", name, typ, asm.LLVMGlobal(GoGlobalName(reg)))
			return wasmValue{typ: typ, val: "%" + name}, nil
		}
		slot, ok := regSlots[reg]
		if !ok {
			return wasmValue{}, fmt.Errorf("register %s is not available", reg)
		}
		if reg == asm.Reg("CTXT") && !regInitialized[reg] {
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
	storeRegister := func(reg asm.Reg, value wasmValue) (wasmValue, error) {
		if useGoStack && wasmGoGlobalRegister(reg) {
			typ, err := registerType(reg)
			if err != nil {
				return wasmValue{}, err
			}
			value, err = cast(value, typ, false)
			if err != nil {
				return wasmValue{}, err
			}
			fmt.Fprintf(b, "  store %s %s, ptr addrspace(1) %s\n", typ, value.val, asm.LLVMGlobal(GoGlobalName(reg)))
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
	addressPtr := func(v wasmValue, offset int64) (wasmValue, error) {
		var err error
		v, err = cast(v, asm.Ptr, false)
		if err != nil {
			return wasmValue{}, err
		}
		if offset == 0 {
			return v, nil
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = getelementptr i8, ptr %s, i32 %d\n", name, v.val, offset)
		return wasmValue{typ: asm.Ptr, val: "%" + name}, nil
	}
	// A Wasm memarg adds its unsigned offset without wrapping at 32 bits.
	// Keep frame-address arithmetic separate; Go frame offsets may be signed.
	memargPtr := func(base wasmValue, offset int64) (wasmValue, error) {
		if offset < 0 || offset > 0xffffffff {
			return wasmValue{}, fmt.Errorf("invalid wasm32 memory offset %d", offset)
		}
		if offset > 0 {
			integer, err := cast(base, asm.I32, false)
			if err != nil {
				return wasmValue{}, err
			}
			wrap := newTmp()
			fmt.Fprintf(b, "  %%%s = icmp ugt i32 %s, %d\n", wrap, integer.val, 0xffffffff-offset)
			emitTrapIf(b, newTmp, wrap)
		}
		return addressPtr(base, offset)
	}
	goFrameAddress := func(offset int64) (wasmValue, error) {
		sp, err := loadRegister(asm.SP)
		if err != nil {
			return wasmValue{}, err
		}
		return addressPtr(sp, fn.FrameSize+8+offset)
	}
	frameParam := func(arg asm.Operand, width asm.LLVMType) (wasmValue, error) {
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
				fmt.Fprintf(b, "  %%%s = load volatile %s, ptr %s, align 1\n", name, width, address.val)
				return wasmValue{typ: width, val: "%" + name}, nil
			}
			if slot.Index < 0 || slot.Index >= len(sig.Args) {
				return wasmValue{}, fmt.Errorf("FP parameter %s has invalid argument index %d", arg, slot.Index)
			}
			value := fmt.Sprintf("%%arg%d", slot.Index)
			if slot.Field >= 0 {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = extractvalue %s %s, %d\n", name, sig.Args[slot.Index], value, slot.Field)
				value = "%" + name
			}
			return wasmValue{typ: slot.Type, val: value}, nil
		}
		return wasmValue{}, fmt.Errorf("unknown FP parameter %s", arg)
	}
	storeResult := func(arg asm.Operand, value wasmValue, explicitBase *wasmValue) error {
		for _, slot := range sig.Frame.Results {
			if slot.Offset != arg.FPOffset {
				continue
			}
			if useGoStack {
				var address wasmValue
				var err error
				if explicitBase != nil {
					address, err = memargPtr(*explicitBase, fn.FrameSize+8+arg.FPOffset)
				} else {
					address, err = goFrameAddress(arg.FPOffset)
				}
				if err != nil {
					return err
				}
				fmt.Fprintf(b, "  store volatile %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
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
			if len(sig.Frame.Results) > 1 {
				return errors.New("multiple FP result slots are unsupported by the direct WebAssembly ABI")
			}
			fmt.Fprintf(b, "  store %s %s, ptr %%wasm_fp_result\n", value.typ, value.val)
			resultState = resultStored
			return nil
		}
		return fmt.Errorf("unknown FP result %s", arg)
	}
	// Go wasm store instructions consume an explicit address below the value.
	// MOV pseudo-instructions synthesize their frame address separately.
	storeStackResult := func(op string, arg asm.Operand, v wasmValue) error {
		if useGoStack {
			base, err := pop(op)
			if err != nil {
				return err
			}
			return storeResult(arg, v, &base)
		}
		if len(stack) != 0 && stack[len(stack)-1].stackAddr {
			stack = stack[:len(stack)-1]
		}
		return storeResult(arg, v, nil)
	}
	loadOperand := func(arg asm.Operand, width asm.LLVMType) (wasmValue, error) {
		var v wasmValue
		var err error
		switch arg.Kind {
		case asm.OpFP:
			v, err = frameParam(arg, width)
		case asm.OpFPAddr:
			if !useGoStack {
				return wasmValue{}, fmt.Errorf("linear-memory FP addresses require the Go WebAssembly ABI")
			}
			v, err = goFrameAddress(arg.FPOffset)
		case asm.OpReg:
			v, err = loadRegister(arg.Reg)
		case asm.OpImm:
			v = wasmValue{typ: width, val: fmt.Sprintf("%d", arg.Imm)}
		case asm.OpSym:
			isAddress := strings.HasPrefix(strings.TrimSpace(arg.Sym), "$")
			if isAddress {
				if mem, matched, memErr := asm.ParseWASMMem(strings.TrimSpace(strings.TrimPrefix(arg.Sym, "$"))); matched {
					if memErr != nil {
						return wasmValue{}, memErr
					}
					if mem.OffRaw != "" {
						return wasmValue{}, fmt.Errorf("unresolved wasm memory offset %q", mem.OffRaw)
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
			if !strings.HasSuffix(arg.Sym, "(SB)") {
				return wasmValue{}, fmt.Errorf("unresolved wasm symbol %s", arg.Sym)
			}
			base, offset, ok := asm.ParseSBRef(arg.Sym)
			if !ok {
				return wasmValue{}, fmt.Errorf("unsupported wasm symbol address %s", arg)
			}
			base = strings.TrimPrefix(base, "$")
			resolved := resolve(base)
			if _, fn := sigs[resolved]; !fn && !strings.ContainsAny(base, "·/.") {
				resolved = resolve("·" + base)
			}
			v = wasmValue{typ: asm.Ptr, val: asm.LLVMGlobal(resolved)}
			if fsig, found := sigs[resolved]; found && isAddress && useGoStack {
				if offset != 0 {
					return wasmValue{}, fmt.Errorf("unsupported Go function PC addend %d", offset)
				}
				fnPC := newTmp()
				v.val = asm.LLVMGlobal(asm.FuncSigSymbol(resolved, fsig))
				fmt.Fprintf(b, "  %%%s = shl i64 ptrtoint (ptr %s to i64), 16\n", fnPC, v.val)
				v = wasmValue{typ: asm.I64, val: "%" + fnPC}
				break
			}
			if offset != 0 {
				v, err = addressPtr(v, offset)
				if err != nil {
					return wasmValue{}, err
				}
			}
			if !isAddress {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = load volatile %s, ptr %s, align 1\n", name, width, v.val)
				v = wasmValue{typ: width, val: "%" + name}
			}
		case asm.OpMem:
			if arg.Mem.Base == asm.SP && !useGoStack {
				return wasmValue{}, fmt.Errorf("linear-memory SP operands are not available in the direct Go ABI")
			}
			base, loadErr := loadRegister(arg.Mem.Base)
			if loadErr != nil {
				return wasmValue{}, fmt.Errorf("load %s: %w", arg, loadErr)
			}
			address, addressErr := memargPtr(base, arg.Mem.Off)
			if addressErr != nil {
				return wasmValue{}, addressErr
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = load volatile %s, ptr %s, align 1\n", name, width, address.val)
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
	storeOperand := func(arg asm.Operand, value wasmValue) error {
		switch arg.Kind {
		case asm.OpReg:
			_, err := storeRegister(arg.Reg, value)
			return err
		case asm.OpFP:
			return storeResult(arg, value, nil)
		case asm.OpMem:
			if arg.Mem.Base == asm.SP && !useGoStack {
				return fmt.Errorf("linear-memory SP operands are not available in the direct Go ABI")
			}
			base, err := loadRegister(arg.Mem.Base)
			if err != nil {
				return fmt.Errorf("store %s: %w", arg, err)
			}
			address, err := memargPtr(base, arg.Mem.Off)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  store volatile %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
			return nil
		case asm.OpSym:
			base, offset, ok := asm.ParseSBRef(arg.Sym)
			if !ok {
				return fmt.Errorf("unsupported wasm symbol destination %s", arg)
			}
			base = strings.TrimPrefix(base, "$")
			if !strings.ContainsAny(base, "·/.") {
				base = "·" + base
			}
			address := wasmValue{typ: asm.Ptr, val: asm.LLVMGlobal(resolve(base))}
			if offset != 0 {
				var err error
				address, err = addressPtr(address, offset)
				if err != nil {
					return err
				}
			}
			fmt.Fprintf(b, "  store volatile %s %s, ptr %s, align 1\n", value.typ, value.val, address.val)
			return nil
		default:
			return fmt.Errorf("unsupported wasm destination operand %s", arg)
		}
	}
	emitReturn := func() error {
		if goABI {
			sp, err := loadRegister(asm.SP)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", name, sp.val, fn.FrameSize+8)
			if _, err := storeRegister(asm.SP, wasmValue{typ: asm.I32, val: "%" + name}); err != nil {
				return err
			}
			b.WriteString("  ret i32 0\n")
			blockTerminated = true
			return nil
		}
		if len(sig.Frame.Results) > 1 {
			return errors.New("multiple FP result slots are unsupported by the direct WebAssembly ABI")
		}
		if sig.Ret == asm.Void {
			b.WriteString("  ret void\n")
			blockTerminated = true
			return nil
		}
		if resultState == resultStored|resultUnset {
			return fmt.Errorf("FP result is only written on some paths to RET")
		}
		var value wasmValue
		if resultState == resultStored {
			typ := sig.Frame.Results[0].Type
			if typ != sig.Ret && !(isWasmV128(typ) && isWasmV128(sig.Ret)) {
				return fmt.Errorf("return type %s does not match stored result %s", sig.Ret, typ)
			}
			ret := newTmp()
			fmt.Fprintf(b, "  %%%s = load %s, ptr %%wasm_fp_result\n", ret, typ)
			value = wasmValue{typ: typ, val: "%" + ret}
		} else if len(stack) > 0 {
			value = stack[len(stack)-1]
		}
		if isWasmV128(value.typ) && isWasmV128(sig.Ret) {
			var err error
			value, err = cast(value, sig.Ret, false)
			if err != nil {
				return err
			}
		}
		if !value.stackAddr && value.typ == sig.Ret {
			fmt.Fprintf(b, "  ret %s %s\n", sig.Ret, value.val)
			blockTerminated = true
			return nil
		}
		return fmt.Errorf("missing %s return value", sig.Ret)
	}
	emitRawReturn := func() error {
		if physicalRet == asm.Void {
			b.WriteString("  ret void\n")
			blockTerminated = true
			return nil
		}
		v, err := pop("Return")
		if err != nil {
			return err
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
		sp, err := loadRegister(asm.SP)
		if err != nil {
			return err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", name, sp.val, fn.FrameSize+8)
		if _, err := storeRegister(asm.SP, wasmValue{typ: asm.I32, val: "%" + name}); err != nil {
			return err
		}
		b.WriteString("  ret i32 1\n")
		blockTerminated = true
		return nil
	}
	emitTailCall := func(arg asm.Operand) error {
		if goABI && arg.Kind == asm.OpInvalid {
			target, err := pop("JMP")
			if err != nil {
				return err
			}
			target, err = cast(target, asm.I64, false)
			if err != nil {
				return err
			}
			pcFunc := newTmp()
			fmt.Fprintf(b, "  %%%s = lshr i64 %s, 16\n", pcFunc, target.val)
			target32, err := cast(wasmValue{typ: asm.I64, val: "%" + pcFunc}, asm.I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target32, asm.Ptr, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = tail call i32 %s(i32 0)\n", name, targetPtr.val)
			fmt.Fprintf(b, "  ret i32 %%%s\n", name)
			blockTerminated = true
			return nil
		}
		if arg.Kind != asm.OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
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
			fmt.Fprintf(b, "  %%%s = tail call i32 %s(i32 0)\n", name, asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig)))
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
			context, err := loadRegister(asm.Reg("CTXT"))
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
		if calleeSig.Ret == asm.Void {
			fmt.Fprintf(b, "  tail call void %s(%s)\n  ret void\n", asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig)), args.String())
		} else {
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = tail call %s %s(%s)\n", name, calleeSig.Ret, asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig)), args.String())
			fmt.Fprintf(b, "  ret %s %%%s\n", calleeSig.Ret, name)
		}
		blockTerminated = true
		return nil
	}
	emitLocalCall := func(arg asm.Operand) error {
		if arg.Kind != asm.OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
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
			argTypes = []asm.LLVMType{asm.I32}
			retType = asm.I32
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
			context, err := loadRegister(asm.Reg("CTXT"))
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
		if retType == asm.Void {
			fmt.Fprintf(b, "  call void %s(%s)\n", asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig)), argText.String())
			return nil
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = call %s %s(%s)\n", name, retType, asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig)), argText.String())
		push(wasmValue{typ: retType, val: "%" + name})
		return nil
	}
	isSigpanic := func(arg asm.Operand) bool {
		if arg.Kind != asm.OpSym {
			return false
		}
		raw := strings.TrimSuffix(arg.Sym, "(SB)")
		return raw == "runtime·sigpanic" || raw == "runtime.sigpanic" || resolve(raw) == "runtime.sigpanic"
	}
	emitGoCall := func(arg asm.Operand, pcID int, resumeLabel string, canResume bool) error {
		if !useGoStack {
			return fmt.Errorf("Go ABI CALL requires the Go WebAssembly ABI")
		}
		if canResume && resumeLabel == "" {
			return errors.New("resumable Go ABI CALL is missing its resume label")
		}
		callee := ""
		calleeSig := asm.FuncSig{}
		callTarget := ""
		if arg.Kind == asm.OpInvalid {
			target, err := pop("CALL")
			if err != nil {
				return err
			}
			target, err = cast(target, asm.I64, false)
			if err != nil {
				return err
			}
			pcFunc := newTmp()
			fmt.Fprintf(b, "  %%%s = lshr i64 %s, 16\n", pcFunc, target.val)
			target32, err := cast(wasmValue{typ: asm.I64, val: "%" + pcFunc}, asm.I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target32, asm.Ptr, false)
			if err != nil {
				return err
			}
			callTarget = targetPtr.val
		} else {
			if arg.Kind != asm.OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
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
			callTarget = asm.LLVMGlobal(asm.FuncSigSymbol(callee, calleeSig))
		}
		if len(stack) != 0 {
			return fmt.Errorf("Go ABI CALL requires an otherwise empty WebAssembly operand stack")
		}

		sp, err := loadRegister(asm.SP)
		if err != nil {
			return err
		}
		callerSP := newTmp()
		fmt.Fprintf(b, "  %%%s = sub i32 %s, 8\n", callerSP, sp.val)
		if _, err := storeRegister(asm.SP, wasmValue{typ: asm.I32, val: "%" + callerSP}); err != nil {
			return err
		}
		callerAddr, err := cast(wasmValue{typ: asm.I32, val: "%" + callerSP}, asm.Ptr, false)
		if err != nil {
			return err
		}
		pcFunc := newTmp()
		fmt.Fprintf(b, "  %%%s = ptrtoint ptr %s to i64\n", pcFunc, asm.LLVMGlobal(sig.Name))
		pcBase := newTmp()
		fmt.Fprintf(b, "  %%%s = shl i64 %%%s, 16\n", pcBase, pcFunc)
		pc := "%" + pcBase
		if pcID != 0 {
			pcValue := newTmp()
			fmt.Fprintf(b, "  %%%s = or i64 %%%s, %d\n", pcValue, pcBase, pcID)
			pc = "%" + pcValue
		}
		fmt.Fprintf(b, "  store i64 %s, ptr %s, align 1\n", pc, callerAddr.val)
		unwind := newTmp()
		fmt.Fprintf(b, "  %%%s = call i32 %s(i32 0)\n", unwind, callTarget)
		isUnwind := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp ne i32 %%%s, 0\n", isUnwind, unwind)
		unwindLabel := "wasm_call_unwind_" + newTmp()
		if canResume {
			fmt.Fprintf(b, "  br i1 %%%s, label %%%s, label %%%s\n", isUnwind, unwindLabel, resumeLabel)
		} else {
			continueLabel := "wasm_call_continue_" + newTmp()
			fmt.Fprintf(b, "  br i1 %%%s, label %%%s, label %%%s\n", isUnwind, unwindLabel, continueLabel)
			fmt.Fprintf(b, "%s:\n", unwindLabel)
			if isSigpanic(arg) && goABI {
				b.WriteString("  ret i32 1\n")
			} else {
				b.WriteString("  call void @llvm.trap()\n  unreachable\n")
			}
			fmt.Fprintf(b, "%s:\n", continueLabel)
			blockTerminated = false
			return nil
		}
		fmt.Fprintf(b, "%s:\n  ret i32 1\n%s:\n", unwindLabel, resumeLabel)
		blockTerminated = false
		return nil
	}
	emitIntBinary := func(op string, typ asm.LLVMType, llvmOp string) error {
		rhs, err := pop(op)
		if err != nil {
			return err
		}
		lhs, err := pop(op)
		if err != nil {
			return err
		}
		lhs, err = cast(lhs, typ, false)
		if err != nil {
			return err
		}
		rhs, err = cast(rhs, typ, false)
		if err != nil {
			return err
		}
		width := 32
		if typ == asm.I64 {
			width = 64
		}
		switch llvmOp {
		case "shl", "ashr", "lshr":
			count := newTmp()
			fmt.Fprintf(b, "  %%%s = and %s %s, %d\n", count, typ, rhs.val, width-1)
			rhs.val = "%" + count
		case "sdiv", "udiv", "srem", "urem":
			invalid := newTmp()
			fmt.Fprintf(b, "  %%%s = icmp eq %s %s, 0\n", invalid, typ, rhs.val)
			if llvmOp == "sdiv" {
				min, negOne, overflow, either := newTmp(), newTmp(), newTmp(), newTmp()
				fmt.Fprintf(b, "  %%%s = icmp eq %s %s, %d\n", min, typ, lhs.val, int64(-1)<<(width-1))
				fmt.Fprintf(b, "  %%%s = icmp eq %s %s, -1\n", negOne, typ, rhs.val)
				fmt.Fprintf(b, "  %%%s = and i1 %%%s, %%%s\n", overflow, min, negOne)
				fmt.Fprintf(b, "  %%%s = or i1 %%%s, %%%s\n", either, invalid, overflow)
				invalid = either
			}
			emitTrapIf(b, newTmp, invalid)
			if llvmOp == "srem" {
				// MIN % -1 is zero in Wasm. A divisor of +1 gives the
				// same remainder for every dividend without LLVM overflow.
				negOne, safe := newTmp(), newTmp()
				fmt.Fprintf(b, "  %%%s = icmp eq %s %s, -1\n", negOne, typ, rhs.val)
				fmt.Fprintf(b, "  %%%s = select i1 %%%s, %s 1, %s %s\n", safe, negOne, typ, typ, rhs.val)
				rhs.val = "%" + safe
			}
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", name, llvmOp, typ, lhs.val, rhs.val)
		push(wasmValue{typ: typ, val: "%" + name})
		return nil
	}
	emitIntCompare := func(op string, typ asm.LLVMType, pred string, unary bool) error {
		rhs := wasmValue{typ: typ, val: "0"}
		var err error
		if !unary {
			rhs, err = pop(op)
			if err != nil {
				return err
			}
		}
		lhs, err := pop(op)
		if err != nil {
			return err
		}
		lhs, err = cast(lhs, typ, false)
		if err != nil {
			return err
		}
		rhs, err = cast(rhs, typ, false)
		if err != nil {
			return err
		}
		cmp := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp %s %s %s, %s\n", cmp, pred, typ, lhs.val, rhs.val)
		out := newTmp()
		fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
		push(wasmValue{typ: asm.I32, val: "%" + out})
		return nil
	}
	emitMemoryLoad := func(op string, offset int64, spec wasmMemoryLoadOp) error {
		address, err := pop(op)
		if err != nil {
			return err
		}
		address, err = memargPtr(address, offset)
		if err != nil {
			return err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = load volatile %s, ptr %s, align 1\n", name, spec.loadType, address.val)
		v := wasmValue{typ: spec.loadType, val: "%" + name}
		if spec.loadType != spec.resultType {
			v, err = cast(v, spec.resultType, spec.signed)
			if err != nil {
				return err
			}
		}
		push(v)
		return nil
	}
	emitMemoryStore := func(op string, offset int64, spec wasmMemoryStoreOp) error {
		value, err := pop(op)
		if err != nil {
			return err
		}
		address, err := pop(op)
		if err != nil {
			return err
		}
		address, err = memargPtr(address, offset)
		if err != nil {
			return err
		}
		value, err = cast(value, spec.storeType, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "  store volatile %s %s, ptr %s, align 1\n", spec.storeType, value.val, address.val)
		return nil
	}
	root := &wasmControlFrame{kind: "function", endLabel: "wasm_function_return"}
	if physicalRet != asm.Void {
		root.resultType = physicalRet
		root.resultSlot = "wasm_function_result"
		fmt.Fprintf(b, "  %%%s = alloca %s\n", root.resultSlot, root.resultType)
	}
	var (
		controls       = []*wasmControlFrame{root}
		pendingName    string
		rootBranchUsed bool
	)
	copyStack := func(values []wasmValue) []wasmValue {
		return append([]wasmValue(nil), values...)
	}
	newLabel := func(prefix string) string {
		return prefix + "_" + newTmp()
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
		condition, err = cast(condition, asm.I32, false)
		if err != nil {
			return "", err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = icmp ne i32 %s, 0\n", name, condition.val)
		return "%" + name, nil
	}
	storeBlockResult := func(frame *wasmControlFrame, popValue bool) error {
		if frame.resultType == "" {
			return nil
		}
		if len(stack) <= len(frame.baseStack) {
			return fmt.Errorf("%s block is missing its %s result", frame.kind, frame.resultType)
		}
		v := stack[len(stack)-1]
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
		if err := storeBlockResult(frame, true); err != nil {
			return err
		}
		frame.exitResults |= resultState
		fmt.Fprintf(b, "  br label %%%s\n", frame.endLabel)
		blockTerminated = true
		return nil
	}
	controlTarget := func(arg asm.Operand) (*wasmControlFrame, error) {
		if arg.Kind == asm.OpImm {
			depth := int(arg.Imm)
			if depth < 0 || depth >= len(controls) {
				return nil, fmt.Errorf("branch depth %d exceeds %d active controls", depth, len(controls))
			}
			return controls[len(controls)-1-depth], nil
		}
		var name string
		switch arg.Kind {
		case asm.OpIdent:
			name = arg.Ident
		case asm.OpLabel, asm.OpSym:
			name = strings.TrimSuffix(arg.Sym, ":")
		default:
			return nil, fmt.Errorf("unsupported branch target %s", arg)
		}
		for i := len(controls) - 1; i >= 0; i-- {
			if controls[i].name == name {
				return controls[i], nil
			}
		}
		return nil, fmt.Errorf("unknown structured branch target %q", name)
	}
	emitBranch := func(op string, arg asm.Operand, conditional bool) error {
		target, err := controlTarget(arg)
		if err != nil {
			return err
		}
		var condition string
		if conditional {
			condition, err = conditionValue(op)
			if err != nil {
				return err
			}
		}
		if target.kind != "loop" && target.resultType != "" {
			if err := storeBlockResult(target, !conditional); err != nil {
				return err
			}
		}
		if target.kind == "function" {
			rootBranchUsed = true
		}
		if target.kind != "loop" {
			target.exitResults |= resultState
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

	type resumePoint struct {
		pc    int
		label string
	}
	resumePoints := make(map[int]resumePoint)
	callPCs := make(map[int]int)
	if useGoStack {
		pcID, depth := 0, 0
		for i, ins := range fn.Instrs {
			op := asm.NormalizeInstructionOpcode(ins.Op)
			switch op {
			case "BLOCK", "IF", "LOOP":
				depth++
			case "END":
				depth--
			case "CALL", "CALLNORESUME":
				if op == "CALL" && depth != 0 {
					return errors.New("Go ABI CALL requires top-level control flow; use CALLNORESUME inside a block")
				}
				pcID++
				callPCs[i] = pcID
				if len(ins.Args) == 1 && isSigpanic(ins.Args[0]) {
					// Go reserves an extra PC for CALLNORESUME sigpanic so both
					// PC and PC-1 identify the panicking call.
					if op == "CALLNORESUME" {
						pcID++
					} else {
						callPCs[i]--
					}
				}
				if goABI && op == "CALL" {
					// sigpanic saves the PC of the call for its stack trace.
					// Dispatch by the distinct PC after the call.
					resumePoints[i] = resumePoint{pc: pcID, label: fmt.Sprintf("wasm_resume_%d", pcID)}
				}
			}
		}
	}
	if goABI {
		b.WriteString("  br label %wasm_dispatch\nwasm_entry_body:\n")
		if fn.FrameSize != 0 {
			sp, err := loadRegister(asm.SP)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = sub i32 %s, %d\n", name, sp.val, fn.FrameSize)
			if _, err := storeRegister(asm.SP, wasmValue{typ: asm.I32, val: "%" + name}); err != nil {
				return err
			}
		}
	}

	deadDepth := 0
	for insIndex, ins := range fn.Instrs {
		op := asm.NormalizeInstructionOpcode(ins.Op)
		if op == "TEXT" {
			continue
		}
		if annotateSource && ins.Raw != "" {
			fmt.Fprintf(b, "  ; %s\n", strings.ReplaceAll(ins.Raw, "\n", " "))
		}
		if blockTerminated {
			delete(resumePoints, insIndex)
			switch op {
			case "BLOCK", "IF", "LOOP":
				deadDepth++
				continue
			case "END":
				if deadDepth > 0 {
					deadDepth--
					continue
				}
			case "ELSE":
				if deadDepth > 0 {
					continue
				}
			default:
				continue
			}
		}
		for _, arg := range ins.Args {
			if arg.Kind == asm.OpImm && arg.ImmRaw != "" {
				return fmt.Errorf("%s: unresolved immediate %s", op, arg.ImmRaw)
			}
		}
		if spec, ok := wasmIntegerBinaryOps[op]; ok {
			if err := emitIntBinary(op, spec.typ, spec.op); err != nil {
				return err
			}
			continue
		}
		if spec, ok := wasmIntegerCompareOps[op]; ok {
			if err := emitIntCompare(op, spec.typ, spec.op, false); err != nil {
				return err
			}
			continue
		}
		if spec, ok := wasmMemoryLoadOps[op]; ok {
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one operand", ins.Op)
			}
			if ins.Args[0].Kind == asm.OpFP || ins.Args[0].Kind == asm.OpMem {
				v, err := loadOperand(ins.Args[0], spec.loadType)
				if err != nil {
					return err
				}
				if spec.loadType != spec.resultType {
					v, err = cast(v, spec.resultType, spec.signed)
					if err != nil {
						return err
					}
				}
				push(v)
				continue
			}
			if ins.Args[0].Kind != asm.OpImm {
				return fmt.Errorf("%s expects an FP slot or immediate memory offset, got %s", ins.Op, ins.Args[0])
			}
			if err := emitMemoryLoad(op, ins.Args[0].Imm, spec); err != nil {
				return err
			}
			continue
		}
		if spec, ok := wasmMemoryStoreOps[op]; ok {
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one operand", ins.Op)
			}
			if ins.Args[0].Kind != asm.OpFP {
				if ins.Args[0].Kind != asm.OpImm {
					return fmt.Errorf("%s expects an FP slot or immediate memory offset, got %s", ins.Op, ins.Args[0])
				}
				if err := emitMemoryStore(op, ins.Args[0].Imm, spec); err != nil {
					return err
				}
				continue
			}
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = cast(v, spec.storeType, false)
			if err != nil {
				return err
			}
			if err := storeStackResult(op, ins.Args[0], v); err != nil {
				return err
			}
			continue
		}
		switch op {
		case "NOP", "NO_LOCAL_POINTERS":
			continue
		case "LABEL":
			if len(ins.Args) != 1 {
				return fmt.Errorf("wasm label expects one name")
			}
			pendingName = strings.TrimSuffix(ins.Args[0].Sym, ":")
		case "BLOCK", "LOOP", "IF":
			resultType := asm.LLVMType("")
			if len(ins.Args) == 1 {
				if ins.Args[0].Kind != asm.OpImm {
					return fmt.Errorf("%s block type must be an immediate", ins.Op)
				}
				resultType = wasmBlockResultType(ins.Args[0].Imm)
				if resultType == "" {
					return fmt.Errorf("%s has unsupported block type $%d", ins.Op, ins.Args[0].Imm)
				}
			} else if len(ins.Args) != 0 {
				return fmt.Errorf("%s expects at most one block type", ins.Op)
			}
			frame := &wasmControlFrame{
				kind:         strings.ToLower(op),
				entryResults: resultState,
				name:         pendingName,
				endLabel:     newLabel("wasm_control_end"),
				baseStack:    copyStack(stack),
				resultType:   resultType,
			}
			pendingName = ""
			if resultType != "" {
				frame.resultSlot = fmt.Sprintf("wasm_control_result_%d", insIndex)
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
			resultState = frame.entryResults
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
				resultState = frame.entryResults
				if frame.resultType != "" {
					return fmt.Errorf("result-producing If requires Else")
				}
			}
			if err := finishControlPath(frame); err != nil {
				return err
			}
			stack = copyStack(frame.baseStack)
			emitLabel(frame.endLabel)
			resultState = frame.exitResults
			if resultState == 0 {
				b.WriteString("  unreachable\n")
				blockTerminated = true
				continue
			}
			if frame.resultType != "" {
				name := newTmp()
				fmt.Fprintf(b, "  %%%s = load %s, ptr %%%s\n", name, frame.resultType, frame.resultSlot)
				push(wasmValue{typ: frame.resultType, val: "%" + name})
			}
		case "BR", "BRIF":
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one target", ins.Op)
			}
			if err := emitBranch(op, ins.Args[0], op == "BRIF"); err != nil {
				return err
			}
		case "GET", "LOCALGET":
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
				return fmt.Errorf("Get expects one register")
			}
			if ins.Args[0].Reg == asm.SP {
				if useGoStack {
					v, err := loadRegister(asm.SP)
					if err != nil {
						return err
					}
					push(v)
				} else {
					push(wasmValue{typ: asm.I32, val: "0", stackAddr: true})
				}
				continue
			}
			v, err := loadRegister(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			push(v)
		case "SET", "TEE", "LOCALSET", "LOCALTEE":
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
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
			if op == "TEE" || op == "LOCALTEE" {
				push(v)
			}
		case "GLOBALGET":
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
				return fmt.Errorf("wasm: %s expects one modeled global register operand: %q", ins.Op, ins.Raw)
			}
			v, err := loadRegister(ins.Args[0].Reg)
			if err != nil {
				return err
			}
			push(v)
		case "GLOBALSET":
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpReg {
				return fmt.Errorf("wasm: %s expects one modeled global register operand: %q", ins.Op, ins.Raw)
			}
			v, err := pop(op)
			if err != nil {
				return err
			}
			if _, err := storeRegister(ins.Args[0].Reg, v); err != nil {
				return err
			}
		case "BRTABLE":
			idx, err := pop(op)
			if err != nil {
				return err
			}
			idx, err = cast(idx, asm.I32, false)
			if err != nil {
				return err
			}
			if len(ins.Args) == 0 {
				return fmt.Errorf("BrTable expects at least one target")
			}
			labels := make([]string, len(ins.Args))
			var labelType asm.LLVMType
			for i, arg := range ins.Args {
				target, err := controlTarget(arg)
				if err != nil {
					return err
				}
				typ := target.resultType
				labels[i] = target.endLabel
				if target.kind == "loop" {
					typ = ""
					labels[i] = target.startLabel
				}
				if i != 0 && typ != labelType {
					return fmt.Errorf("BrTable target result types disagree: %s and %s", labelType, typ)
				}
				labelType = typ
				if typ != "" {
					if err := storeBlockResult(target, false); err != nil {
						return err
					}
				}
				if target.kind != "loop" {
					target.exitResults |= resultState
				}
				if target == root {
					rootBranchUsed = true
				}
			}
			fmt.Fprintf(b, "  switch i32 %s, label %%%s [", idx.val, labels[len(labels)-1])
			for ci, lbl := range labels[:len(labels)-1] {
				fmt.Fprintf(b, " i32 %d, label %%%s", ci, lbl)
			}
			b.WriteString(" ]\n")
			blockTerminated = true
		case "MOVB", "MOVH", "MOVW", "MOVD":
			if len(ins.Args) != 2 {
				return fmt.Errorf("%s expects source and destination", ins.Op)
			}
			width := map[string]asm.LLVMType{"MOVB": asm.I8, "MOVH": asm.I16, "MOVW": asm.I32, "MOVD": asm.I64}[op]
			v, err := loadOperand(ins.Args[0], width)
			if err != nil {
				return err
			}
			if err := storeOperand(ins.Args[1], v); err != nil {
				return err
			}
		case "I32CONST", "I64CONST":
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one integer immediate", ins.Op)
			}
			typ := asm.I32
			if op == "I64CONST" {
				typ = asm.I64
			}
			if useGoStack && ins.Args[0].Kind == asm.OpFPAddr {
				push(wasmValue{typ: typ, val: fmt.Sprintf("%d", fn.FrameSize+8+ins.Args[0].FPOffset)})
				continue
			}
			if ins.Args[0].Kind == asm.OpImm {
				push(wasmValue{typ: typ, val: fmt.Sprintf("%d", ins.Args[0].Imm)})
				continue
			}
			v, err := loadOperand(ins.Args[0], typ)
			if err != nil {
				return fmt.Errorf("%s expects one integer immediate or symbol address: %w", ins.Op, err)
			}
			push(v)
		case "F64CONST":
			if len(ins.Args) != 1 {
				return fmt.Errorf("F64Const expects one floating immediate")
			}
			switch ins.Args[0].Kind {
			case asm.OpImm:
				push(wasmValue{typ: asm.LLVMType("double"), val: fmt.Sprintf("0x%016X", uint64(ins.Args[0].Imm))})
			case asm.OpSym:
				raw := strings.TrimPrefix(strings.TrimSpace(ins.Args[0].Sym), "$")
				fv, err := strconv.ParseFloat(raw, 64)
				if err != nil {
					return fmt.Errorf("F64Const expects one floating immediate: %w", err)
				}
				push(wasmValue{typ: asm.LLVMType("double"), val: asm.FormatLLVMFloat64Literal(fv)})
			default:
				return fmt.Errorf("F64Const expects one floating immediate")
			}
		case "F64NE", "F64GT", "F64LT":
			rhs, err := pop(op)
			if err != nil {
				return err
			}
			lhs, err := pop(op)
			if err != nil {
				return err
			}
			if lhs.typ != asm.LLVMType("double") || rhs.typ != asm.LLVMType("double") {
				return fmt.Errorf("%s expects two f64 values", ins.Op)
			}
			pred := map[string]string{"F64NE": "une", "F64GT": "ogt", "F64LT": "olt"}[op]
			cmp := newTmp()
			fmt.Fprintf(b, "  %%%s = fcmp %s double %s, %s\n", cmp, pred, lhs.val, rhs.val)
			out := newTmp()
			fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
			push(wasmValue{typ: asm.I32, val: "%" + out})
		case "I64TRUNCF64S", "I64TRUNCF64U":
			v, err := pop(op)
			if err != nil {
				return err
			}
			if v.typ != asm.LLVMType("double") {
				return fmt.Errorf("%s expects an f64 value", ins.Op)
			}
			res := emitWasmCheckedFloatTrunc(b, newTmp, asm.LLVMType("double"), asm.I64, op == "I64TRUNCF64S", v.val)
			push(wasmValue{typ: asm.I64, val: res})
		case "F32LOAD", "F64LOAD":
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm {
				ext := wasmExtState{b: b, newTmp: newTmp, push: push, pop: pop, cast: cast, addressPtr: memargPtr}
				if _, err := ext.lowerExtOp(op, ins); err != nil {
					return err
				}
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpFP {
				return fmt.Errorf("%s expects an FP slot or offset", ins.Op)
			}
			loadTy := asm.LLVMType("double")
			if op == "F32LOAD" {
				loadTy = asm.LLVMType("float")
			}
			v, err := loadOperand(ins.Args[0], loadTy)
			if err != nil {
				return err
			}
			push(v)
		case "I32WRAPI64":
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = cast(v, asm.I32, false)
			if err != nil {
				return err
			}
			push(v)
		case "I64EXTENDI32U", "I64EXTENDI32S":
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = cast(v, asm.I64, op == "I64EXTENDI32S")
			if err != nil {
				return err
			}
			push(v)
		case "I32EQZ", "NOT":
			if err := emitIntCompare(op, asm.I32, "eq", true); err != nil {
				return err
			}
		case "I64EQZ":
			if err := emitIntCompare(op, asm.I64, "eq", true); err != nil {
				return err
			}
		case "SELECT":
			condition, err := pop(op)
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
			if ifTrue.typ != ifFalse.typ && isWasmV128(ifTrue.typ) && isWasmV128(ifFalse.typ) {
				ifFalse, err = cast(ifFalse, ifTrue.typ, false)
				if err != nil {
					return err
				}
			}
			if ifTrue.typ != ifFalse.typ {
				return fmt.Errorf("Select value type mismatch: %s and %s", ifTrue.typ, ifFalse.typ)
			}
			condition, err = cast(condition, asm.I32, false)
			if err != nil {
				return err
			}
			cmp := newTmp()
			fmt.Fprintf(b, "  %%%s = icmp ne i32 %s, 0\n", cmp, condition.val)
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = select i1 %%%s, %s %s, %s %s\n", name, cmp, ifTrue.typ, ifTrue.val, ifFalse.typ, ifFalse.val)
			push(wasmValue{typ: ifTrue.typ, val: "%" + name})
		case "DROP":
			if _, err := pop(op); err != nil {
				return err
			}
		case "F64FLOOR", "F64CEIL", "F64TRUNC":
			v, err := pop(op)
			if err != nil {
				return err
			}
			if v.typ != asm.LLVMType("double") || v.stackAddr {
				return fmt.Errorf("%s expects f64, got %s", op, v.typ)
			}
			intrinsic := strings.ToLower(strings.TrimPrefix(op, "F64"))
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call double @llvm.%s.f64(double %s)\n", name, intrinsic, v.val)
			push(wasmValue{typ: asm.LLVMType("double"), val: "%" + name})
		case "F32STORE", "F64STORE":
			if len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpImm {
				ext := wasmExtState{b: b, newTmp: newTmp, push: push, pop: pop, cast: cast, addressPtr: memargPtr}
				if _, err := ext.lowerExtOp(op, ins); err != nil {
					return err
				}
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpFP {
				return fmt.Errorf("%s expects an FP slot or offset", ins.Op)
			}
			v, err := pop(op)
			if err != nil {
				return err
			}
			want := asm.LLVMType("double")
			if op == "F32STORE" {
				want = "float"
			}
			if v.typ != want {
				return fmt.Errorf("%s expects %s, got %s", ins.Op, want, v.typ)
			}
			if err := storeStackResult(op, ins.Args[0], v); err != nil {
				return err
			}
		case "CURRENTMEMORY", "MEMORYSIZE":
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.size.i32(i32 0)\n", name)
			push(wasmValue{typ: asm.I32, val: "%" + name})
		case "GROWMEMORY", "MEMORYGROW":
			pages, err := pop(op)
			if err != nil {
				return err
			}
			pages, err = cast(pages, asm.I32, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.grow.i32(i32 0, i32 %s)\n", name, pages.val)
			push(wasmValue{typ: asm.I32, val: "%" + name})
		case "MEMORYCOPY":
			length, err := pop(op)
			if err != nil {
				return err
			}
			src, err := pop(op)
			if err != nil {
				return err
			}
			dst, err := pop(op)
			if err != nil {
				return err
			}
			length, err = cast(length, asm.I32, false)
			if err != nil {
				return err
			}
			src, err = cast(src, asm.Ptr, false)
			if err != nil {
				return err
			}
			dst, err = cast(dst, asm.Ptr, false)
			if err != nil {
				return err
			}
			emitBulkBoundsCheck(b, newTmp, length.val, dst.val, src.val)
			fmt.Fprintf(b, "  call void @llvm.memmove.p0.p0.i32(ptr %s, ptr %s, i32 %s, i1 false)\n", dst.val, src.val, length.val)
		case "MEMORYFILL":
			length, err := pop(op)
			if err != nil {
				return err
			}
			fill, err := pop(op)
			if err != nil {
				return err
			}
			dst, err := pop(op)
			if err != nil {
				return err
			}
			length, err = cast(length, asm.I32, false)
			if err != nil {
				return err
			}
			fill, err = cast(fill, asm.I8, false)
			if err != nil {
				return err
			}
			dst, err = cast(dst, asm.Ptr, false)
			if err != nil {
				return err
			}
			emitBulkBoundsCheck(b, newTmp, length.val, dst.val)
			fmt.Fprintf(b, "  call void @llvm.memset.p0.i32(ptr %s, i8 %s, i32 %s, i1 false)\n", dst.val, fill.val, length.val)
		case "RET":
			if len(ins.Args) == 1 {
				if goABI && fn.FrameSize != 0 {
					sp, err := loadRegister(asm.SP)
					if err != nil {
						return err
					}
					name := newTmp()
					fmt.Fprintf(b, "  %%%s = add i32 %s, %d\n", name, sp.val, fn.FrameSize)
					if _, err := storeRegister(asm.SP, wasmValue{typ: asm.I32, val: "%" + name}); err != nil {
						return err
					}
				}
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
		case "WASMRETURN", "RETURN":
			if useGoStack {
				if err := emitRawReturn(); err != nil {
					return err
				}
			} else if err := emitReturn(); err != nil {
				return err
			}
		case "JMP":
			if len(ins.Args) > 1 || len(ins.Args) == 0 && !goABI {
				return fmt.Errorf("JMP expects one target")
			}
			target := asm.Operand{}
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
			target := asm.Operand{}
			if len(ins.Args) == 1 {
				target = ins.Args[0]
			}
			// Only the Go ABI entry has a PC_B resume switch. Native helpers
			// still use the linear Go stack for calls, but continue directly
			// after a normally returning callee.
			if err := emitGoCall(target, callPCs[insIndex], resumePoints[insIndex].label, op == "CALL" && goABI); err != nil {
				return err
			}
		case "CALLINDIRECT":
			if !useGoStack {
				return fmt.Errorf("CallIndirect requires the Go WebAssembly ABI")
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpImm || ins.Args[0].Imm != 0 {
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
			target, err = cast(target, asm.I32, false)
			if err != nil {
				return err
			}
			pcB, err = cast(pcB, asm.I32, false)
			if err != nil {
				return err
			}
			targetPtr, err := cast(target, asm.Ptr, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 %s(i32 %s)\n", name, targetPtr.val, pcB.val)
			push(wasmValue{typ: asm.I32, val: "%" + name})
		case "CALLIMPORT":
			if !useGoStack {
				return fmt.Errorf("CallImport requires the Go WebAssembly ABI")
			}
			sp, err := loadRegister(asm.SP)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  call void %s(i32 %s)\n", asm.LLVMGlobal(resolve(fn.Sym)+"$wasmimport"), sp.val)
		case "WASMCALL":
			if len(ins.Args) != 1 {
				return fmt.Errorf("Call expects one target")
			}
			if err := emitLocalCall(ins.Args[0]); err != nil {
				return err
			}
		case "UNDEF", "UNREACHABLE":
			b.WriteString("  call void @llvm.trap()\n  unreachable\n")
			blockTerminated = true
		default:
			ext := wasmExtState{b: b, newTmp: newTmp, push: push, pop: pop, cast: cast, addressPtr: memargPtr}
			handled, err := ext.lowerExtOp(op, ins)
			if err != nil {
				return err
			}
			if !handled {
				return fmt.Errorf("unsupported wasm instruction %s", ins.Op)
			}
		}
	}
	if deadDepth != 0 || len(controls) != 1 {
		return fmt.Errorf("%d unterminated wasm control blocks", len(controls)-1+deadDepth)
	}
	if !blockTerminated {
		if useGoStack && sig.WASMNative && physicalRet != asm.Void {
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
	if goABI {
		b.WriteString("wasm_dispatch:\n  switch i32 %pc_b, label %wasm_entry_body [")
		for i := range fn.Instrs {
			if point, ok := resumePoints[i]; ok {
				fmt.Fprintf(b, " i32 %d, label %%%s", point.pc, point.label)
			}
		}
		b.WriteString(" ]\n")
	}
	b.WriteString("}\n")
	return nil
}

// wasmNeedsIncomingContext reports whether fn reads CTXT before establishing a
// new value itself. LLGo transports this compiler-owned closure environment as
// an explicit physical parameter on WebAssembly; it is intentionally separate
// from the Go signature represented by FuncSig.Args.
func NeedsIncomingContext(fn asm.Func) bool {
	initialized := false
	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		for i, arg := range ins.Args {
			writes := (op == "SET" || op == "TEE") && i == 0 && arg.Kind == asm.OpReg ||
				(op == "MOVB" || op == "MOVW" || op == "MOVD") && i == 1 && arg.Kind == asm.OpReg
			if writes && arg.Reg == asm.Reg("CTXT") {
				initialized = true
				continue
			}
			if (arg.Kind == asm.OpReg && arg.Reg == asm.Reg("CTXT")) ||
				(arg.Kind == asm.OpMem && arg.Mem.Base == asm.Reg("CTXT")) {
				if !initialized {
					return true
				}
			}
		}
	}
	return false
}

func wasmGoGlobalRegister(reg asm.Reg) bool {
	name := strings.ToUpper(string(reg))
	return name == "SP" || name == "CTXT" || name == "G" || name == "PAUSE" ||
		strings.HasPrefix(name, "RET")
}

func GoGlobalName(reg asm.Reg) string {
	if strings.EqualFold(string(reg), "g") {
		return "g"
	}
	return strings.ToUpper(string(reg))
}
