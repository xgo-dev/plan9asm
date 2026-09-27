package plan9asm

import (
	"errors"
	"fmt"
	"strings"
)

type wasmValue struct {
	typ       LLVMType
	val       string
	stackAddr bool
}

type wasmControlFrame struct {
	kind       string
	name       string
	startLabel string
	elseLabel  string
	endLabel   string
	baseStack  []wasmValue
	resultType LLVMType
	resultSlot string
	inElse     bool
}

// translateFuncWASM lowers WebAssembly Plan 9 stack instructions into ordinary
// LLVM SSA. The direct ABI maps FP operands through FuncSig.Frame. The Go ABI
// instead recreates the official compiler's linear-memory stack, register
// globals, resumable calls, and unwind return protocol.
func translateFuncWASM(b *strings.Builder, fn Func, sig FuncSig, resolve func(string) string, sigs map[string]FuncSig, wasmABI WASMABI, annotateSource bool) (err error) {
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

	useGoStack := wasmABI == WASMABIGo
	goABI := useGoStack && !sig.WASMNative
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
	wasmRType := I64
	argRegTypes := make(map[Reg]LLVMType, len(sig.ArgRegs))
	for i, reg := range sig.ArgRegs {
		if i < len(sig.Args) {
			argRegTypes[reg] = sig.Args[i]
		}
		if i >= len(sig.Args) || !strings.HasPrefix(strings.ToUpper(string(reg)), "R") {
			continue
		}
		if sig.Args[i] == I32 || sig.Args[i] == I64 {
			wasmRType = sig.Args[i]
			break
		}
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
	for _, ins := range fn.Instrs {
		for _, arg := range ins.Args {
			var reg Reg
			switch arg.Kind {
			case OpReg:
				reg = arg.Reg
			case OpMem:
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
	emitGoCall := func(arg Operand, pcID int, resumeLabel string, canResume bool) error {
		if !useGoStack {
			return fmt.Errorf("Go ABI CALL requires the Go WebAssembly ABI")
		}
		if canResume && resumeLabel == "" {
			return errors.New("resumable Go ABI CALL is missing its resume label")
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
			fmt.Fprintf(b, "%s:\n  unreachable\n%s:\n", unwindLabel, continueLabel)
			blockTerminated = false
			return nil
		}
		fmt.Fprintf(b, "%s:\n  ret i32 1\n%s:\n", unwindLabel, resumeLabel)
		blockTerminated = false
		return nil
	}
	emitIntBinary := func(op string, typ LLVMType, llvmOp string) error {
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
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = %s %s %s, %s\n", name, llvmOp, typ, lhs.val, rhs.val)
		push(wasmValue{typ: typ, val: "%" + name})
		return nil
	}
	emitIntCompare := func(op string, typ LLVMType, pred string, unary bool) error {
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
	emitMemoryLoad := func(op string, offset int64, spec wasmMemoryLoadOp) error {
		address, err := pop(op)
		if err != nil {
			return err
		}
		address, err = addressPtr(address, offset)
		if err != nil {
			return err
		}
		name := newTmp()
		fmt.Fprintf(b, "  %%%s = load %s, ptr %s, align 1\n", name, spec.loadType, address.val)
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
		address, err = addressPtr(address, offset)
		if err != nil {
			return err
		}
		value, err = cast(value, spec.storeType, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "  store %s %s, ptr %s, align 1\n", spec.storeType, value.val, address.val)
		return nil
	}
	root := &wasmControlFrame{kind: "function", endLabel: "wasm_function_return"}
	if physicalRet != Void {
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
		condition, err = cast(condition, I32, false)
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
		fmt.Fprintf(b, "  br label %%%s\n", frame.endLabel)
		blockTerminated = true
		return nil
	}
	controlTarget := func(arg Operand) (*wasmControlFrame, error) {
		if arg.Kind == OpImm {
			depth := int(arg.Imm)
			if depth < 0 || depth >= len(controls) {
				return nil, fmt.Errorf("branch depth %d exceeds %d active controls", depth, len(controls))
			}
			return controls[len(controls)-1-depth], nil
		}
		var name string
		switch arg.Kind {
		case OpIdent:
			name = arg.Ident
		case OpLabel, OpSym:
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
	emitBranch := func(op string, arg Operand, conditional bool) error {
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
		if target.resultType != "" {
			if err := storeBlockResult(target, !conditional); err != nil {
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

	resumeLabels := make(map[int]string)
	callPCs := make(map[int]int)
	if useGoStack {
		pcID := 0
		for i, ins := range fn.Instrs {
			switch normalizeInstructionOpcode(ins.Op) {
			case "CALL", "CALLNORESUME":
				pcID++
				callPCs[i] = pcID
			}
		}
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
		if blockTerminated && op != "ELSE" && op != "END" && op != "LABEL" {
			continue
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
		if spec, ok := wasmMemoryLoadOps[op]; ok {
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one operand", ins.Op)
			}
			if ins.Args[0].Kind == OpFP || ins.Args[0].Kind == OpMem {
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
			if ins.Args[0].Kind != OpImm {
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
			if ins.Args[0].Kind != OpFP {
				if ins.Args[0].Kind != OpImm {
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
			if len(stack) != 0 && stack[len(stack)-1].stackAddr {
				stack = stack[:len(stack)-1]
			}
			v, err = cast(v, spec.storeType, false)
			if err != nil {
				return err
			}
			if err := storeResult(ins.Args[0], v); err != nil {
				return err
			}
			continue
		}
		switch op {
		case "NOP", "NO_LOCAL_POINTERS", "FUNCDATA", "PCDATA":
			continue
		case "LABEL":
			if len(ins.Args) != 1 {
				return fmt.Errorf("wasm label expects one name")
			}
			pendingName = strings.TrimSuffix(ins.Args[0].Sym, ":")
		case "BLOCK", "LOOP", "IF":
			resultType := LLVMType("")
			if len(ins.Args) == 1 {
				if ins.Args[0].Kind != OpImm {
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
				kind:       strings.ToLower(op),
				name:       pendingName,
				endLabel:   newLabel("wasm_control_end"),
				baseStack:  copyStack(stack),
				resultType: resultType,
			}
			pendingName = ""
			if resultType != "" {
				frame.resultSlot = newLabel("wasm_control_result")
				fmt.Fprintf(b, "  %%%s = alloca %s\n", frame.resultSlot, resultType)
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
			if len(ins.Args) != 1 {
				return fmt.Errorf("%s expects one target", ins.Op)
			}
			if err := emitBranch(op, ins.Args[0], op == "BRIF"); err != nil {
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
		case "MOVB", "MOVW", "MOVD":
			if len(ins.Args) != 2 {
				return fmt.Errorf("%s expects source and destination", ins.Op)
			}
			width := map[string]LLVMType{"MOVB": I8, "MOVW": I32, "MOVD": I64}[op]
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
		case "F64CONST":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm {
				return fmt.Errorf("F64Const expects one floating immediate")
			}
			push(wasmValue{typ: LLVMType("double"), val: fmt.Sprintf("0x%016X", uint64(ins.Args[0].Imm))})
		case "F64NE", "F64GT", "F64LT":
			rhs, err := pop(op)
			if err != nil {
				return err
			}
			lhs, err := pop(op)
			if err != nil {
				return err
			}
			if lhs.typ != LLVMType("double") || rhs.typ != LLVMType("double") {
				return fmt.Errorf("%s expects two f64 values", ins.Op)
			}
			pred := map[string]string{"F64NE": "une", "F64GT": "ogt", "F64LT": "olt"}[op]
			cmp := newTmp()
			fmt.Fprintf(b, "  %%%s = fcmp %s double %s, %s\n", cmp, pred, lhs.val, rhs.val)
			out := newTmp()
			fmt.Fprintf(b, "  %%%s = zext i1 %%%s to i32\n", out, cmp)
			push(wasmValue{typ: I32, val: "%" + out})
		case "I64TRUNCF64S", "I64TRUNCF64U":
			v, err := pop(op)
			if err != nil {
				return err
			}
			if v.typ != LLVMType("double") {
				return fmt.Errorf("%s expects an f64 value", ins.Op)
			}
			llvmOp := "fptosi"
			if op == "I64TRUNCF64U" {
				llvmOp = "fptoui"
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = %s double %s to i64\n", name, llvmOp, v.val)
			push(wasmValue{typ: I64, val: "%" + name})
		case "F64LOAD":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpFP {
				return fmt.Errorf("F64Load expects an FP slot")
			}
			v, err := loadOperand(ins.Args[0], LLVMType("double"))
			if err != nil {
				return err
			}
			push(v)
		case "I32WRAPI64":
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = cast(v, I32, false)
			if err != nil {
				return err
			}
			push(v)
		case "I64EXTENDI32U", "I64EXTENDI32S":
			v, err := pop(op)
			if err != nil {
				return err
			}
			v, err = cast(v, I64, op == "I64EXTENDI32S")
			if err != nil {
				return err
			}
			push(v)
		case "I32EQZ", "NOT":
			if err := emitIntCompare(op, I32, "eq", true); err != nil {
				return err
			}
		case "I64EQZ":
			if err := emitIntCompare(op, I64, "eq", true); err != nil {
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
			if ifTrue.typ != ifFalse.typ {
				return fmt.Errorf("Select value type mismatch: %s and %s", ifTrue.typ, ifFalse.typ)
			}
			condition, err = cast(condition, I32, false)
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
		case "F64STORE":
			if len(ins.Args) != 1 || ins.Args[0].Kind != OpFP {
				return fmt.Errorf("F64Store expects an FP slot")
			}
			v, err := pop(op)
			if err != nil {
				return err
			}
			if len(stack) != 0 && stack[len(stack)-1].stackAddr {
				stack = stack[:len(stack)-1]
			}
			if err := storeResult(ins.Args[0], v); err != nil {
				return err
			}
		case "CURRENTMEMORY":
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.size.i32(i32 0)\n", name)
			push(wasmValue{typ: I32, val: "%" + name})
		case "GROWMEMORY":
			pages, err := pop(op)
			if err != nil {
				return err
			}
			pages, err = cast(pages, I32, false)
			if err != nil {
				return err
			}
			name := newTmp()
			fmt.Fprintf(b, "  %%%s = call i32 @llvm.wasm.memory.grow.i32(i32 0, i32 %s)\n", name, pages.val)
			push(wasmValue{typ: I32, val: "%" + name})
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
			length, err = cast(length, I32, false)
			if err != nil {
				return err
			}
			src, err = cast(src, Ptr, false)
			if err != nil {
				return err
			}
			dst, err = cast(dst, Ptr, false)
			if err != nil {
				return err
			}
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
			length, err = cast(length, I32, false)
			if err != nil {
				return err
			}
			fill, err = cast(fill, I8, false)
			if err != nil {
				return err
			}
			dst, err = cast(dst, Ptr, false)
			if err != nil {
				return err
			}
			fmt.Fprintf(b, "  call void @llvm.memset.p0.i32(ptr %s, i8 %s, i32 %s, i1 false)\n", dst.val, fill.val, length.val)
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
			// Only the Go ABI entry has a PC_B resume switch. Native helpers
			// still use the linear Go stack for calls, but continue directly
			// after a normally returning callee.
			if op == "CALL" && goABI {
				resumeLabels[insIndex] = fmt.Sprintf("wasm_resume_%d", callPCs[insIndex])
			}
			if err := emitGoCall(target, callPCs[insIndex], resumeLabels[insIndex], op == "CALL" && goABI); err != nil {
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
			b.WriteString("  unreachable\n")
			blockTerminated = true
		default:
			return fmt.Errorf("unsupported wasm instruction %s", ins.Op)
		}
	}
	if len(controls) != 1 {
		return fmt.Errorf("%d unterminated wasm control blocks", len(controls)-1)
	}
	if !blockTerminated {
		if useGoStack && sig.WASMNative && physicalRet != Void {
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
		b.WriteString("  switch i32 %pc_b, label %wasm_entry_body [")
		for i := range fn.Instrs {
			if label := resumeLabels[i]; label != "" {
				fmt.Fprintf(b, " i32 %d, label %%%s", callPCs[i], label)
			}
		}
		b.WriteString(" ]\n")
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
		for i, arg := range ins.Args {
			writes := (op == "SET" || op == "TEE") && i == 0 && arg.Kind == OpReg ||
				(op == "MOVB" || op == "MOVW" || op == "MOVD") && i == 1 && arg.Kind == OpReg
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
