package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) resolveBranchTarget(bi int, op Operand) (string, bool) {
	if tgt, ok := arm64BranchTarget(op); ok {
		return tgt, true
	}
	// Plan9's n(PC) is instruction-relative. Our lowering is block-based, so
	// use a conservative target to keep translation total.
	if op.Kind == OpMem && op.Mem.Base == PC {
		if op.Mem.Off <= 0 {
			return c.blocks[bi].name, true
		}
		if bi+1 < len(c.blocks) {
			return c.blocks[bi+1].name, true
		}
		return c.blocks[bi].name, true
	}
	return "", false
}

func (c *arm64Ctx) lowerBranch(bi int, op Op, ins Instr, emitBr arm64EmitBr, emitCondBr arm64EmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "BL", "BLR", "CALL":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 %s expects 1 operand: %q", op, ins.Raw)
		}
		if strings.Contains(strings.ToUpper(string(ins.Op)), ".") {
			return true, false, fmt.Errorf("arm64 %s does not accept a suffix: %q", op, ins.Raw)
		}
		if arm64IsLocalBranchLink(ins) {
			target, targetOK := c.resolveBranchTarget(bi, ins.Args[0])
			if !targetOK {
				return true, false, fmt.Errorf("arm64 %s invalid local target: %q", op, ins.Raw)
			}
			knownTarget := false
			for _, block := range c.blocks {
				if block.name == target {
					knownTarget = true
					break
				}
			}
			if !knownTarget {
				return true, false, fmt.Errorf("arm64 %s undefined local target %q: %q", op, target, ins.Raw)
			}
			if bi+1 >= len(c.blocks) {
				return true, false, fmt.Errorf("arm64 %s local target has no continuation block: %q", op, ins.Raw)
			}
			continuation := c.blocks[bi+1].name
			link := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr blockaddress(%s, %%%s) to i64\n", link, llvmGlobal(c.sig.Name), arm64LLVMBlockName(continuation))
			if err := c.storeReg(Reg("R30"), "%"+link); err != nil {
				return true, false, err
			}
			emitBr(target)
			return true, true, nil
		}
		if ins.Args[0].Kind == OpReg {
			if !isARM64GeneralOrZeroReg(ins.Args[0].Reg) {
				return true, false, fmt.Errorf("arm64 %s expects general register: %q", op, ins.Raw)
			}
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "blr $0", "r,~{memory}", addr)
			return true, false, nil
		}
		if ins.Args[0].Kind == OpMem {
			mem := ins.Args[0].Mem
			baseOK := isARM64GeneralOrZeroReg(mem.Base) || mem.Base == SP || mem.Base == Reg("RSP")
			if !baseOK || mem.Off != 0 || mem.Index != "" {
				return true, false, fmt.Errorf("arm64 %s expects (general register): %q", op, ins.Raw)
			}
			addr, _, _, err := c.addrI64(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "blr $0", "r,~{memory}", addr)
			return true, false, nil
		}
		if ins.Args[0].Kind != OpSym || !strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, false, fmt.Errorf("arm64 %s expects symbol(SB)|reg|mem: %q", op, ins.Raw)
		}
		if err := c.callSym(ins.Args[0]); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "B", "JMP":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 B expects 1 operand: %q", ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if c.flagFlow != nil {
				c.flagFlow.blocks[c.flagFlow.current].indirect = true
			}
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "br $0", "r,~{memory}", addr)
			c.lowerRetZero()
			return true, true, nil
		}
		if ins.Args[0].Kind == OpMem {
			if c.flagFlow != nil {
				c.flagFlow.blocks[c.flagFlow.current].indirect = true
			}
			addr, _, _, err := c.addrI64(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "br $0", "r,~{memory}", addr)
			c.lowerRetZero()
			return true, true, nil
		}
		if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		tgt, ok := arm64BranchTarget(ins.Args[0])
		if !ok {
			// Legacy loop form in runtime stubs: B 0(PC)
			if ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base == PC {
				emitBr(c.blocks[bi].name)
				return true, true, nil
			}
			return true, false, fmt.Errorf("arm64 B invalid target: %q", ins.Raw)
		}
		emitBr(tgt)
		return true, true, nil

	case "BEQ", "BNE", "BLO", "BLT", "BHI", "BHS", "BLS", "BGE", "BGT", "BLE", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 %s expects label: %q", op, ins.Raw)
		}
		tgt, ok := arm64BranchTarget(ins.Args[0])
		if !ok {
			if ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base == PC {
				// Relative PC branch in generated stubs; best-effort: use fallthrough.
				if bi+1 < len(c.blocks) {
					tgt = c.blocks[bi+1].name
					ok = true
				}
			}
		}
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid target: %q", op, ins.Raw)
		}
		fall := ""
		if bi+1 < len(c.blocks) {
			fall = c.blocks[bi+1].name
		}
		if fall == "" {
			return true, false, fmt.Errorf("arm64 %s needs fallthrough block: %q", op, ins.Raw)
		}
		cond := ""
		switch op {
		case "BEQ":
			cond = "EQ"
		case "BNE":
			cond = "NE"
		case "BLO":
			cond = "LO"
		case "BCC":
			cond = "LO"
		case "BLT":
			cond = "LT"
		case "BHI":
			cond = "HI"
		case "BHS":
			cond = "HS"
		case "BLS":
			cond = "LS"
		case "BCS":
			cond = "HS"
		case "BGE":
			cond = "GE"
		case "BGT":
			cond = "GT"
		case "BLE":
			cond = "LE"
		case "BMI":
			cond = "MI"
		case "BPL":
			cond = "PL"
		case "BVS":
			cond = "VS"
		case "BVC":
			cond = "VC"
		}
		if err := emitCondBr(cond, tgt, fall); err != nil {
			return true, false, err
		}
		return true, true, nil

	case "CBZ", "CBNZ":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects reg, label: %q", op, ins.Raw)
		}
		rv, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		if op == "CBZ" {
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", t, rv)
		} else {
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %s, 0\n", t, rv)
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[1])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid target: %q", op, ins.Raw)
		}
		fall := ""
		if bi+1 < len(c.blocks) {
			fall = c.blocks[bi+1].name
		}
		if fall == "" {
			return true, false, fmt.Errorf("arm64 %s needs fallthrough block: %q", op, ins.Raw)
		}
		c.emitPredicateBranch("%"+t, tgt, fall)
		return true, true, nil

	case "TBZ", "TBNZ":
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects $bit, reg, label: %q", op, ins.Raw)
		}
		bit := ins.Args[0].Imm
		rv, err := c.loadReg(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", sh, rv, bit)
		mask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", mask, sh)
		condT := c.newTmp()
		if op == "TBZ" {
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, 0\n", condT, mask)
		} else {
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", condT, mask)
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[2])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid target: %q", op, ins.Raw)
		}
		fall := ""
		if bi+1 < len(c.blocks) {
			fall = c.blocks[bi+1].name
		}
		if fall == "" {
			return true, false, fmt.Errorf("arm64 %s needs fallthrough block: %q", op, ins.Raw)
		}
		c.emitPredicateBranch("%"+condT, tgt, fall)
		return true, true, nil

	case "CBZW", "CBNZW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s expects reg, label: %q", op, ins.Raw)
		}
		rv, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return true, false, err
		}
		w := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", w, rv)
		t := c.newTmp()
		if op == "CBZW" {
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", t, w)
		} else {
			fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", t, w)
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[1])
		if !ok {
			return true, false, fmt.Errorf("arm64 %s invalid target: %q", op, ins.Raw)
		}
		fall := ""
		if bi+1 < len(c.blocks) {
			fall = c.blocks[bi+1].name
		}
		if fall == "" {
			return true, false, fmt.Errorf("arm64 %s needs fallthrough block: %q", op, ins.Raw)
		}
		c.emitPredicateBranch("%"+t, tgt, fall)
		return true, true, nil
	}
	return false, false, nil
}

func (c *arm64Ctx) castI64RegToArg(v string, to LLVMType) (string, error) {
	switch to {
	case I64:
		return v, nil
	case I32, I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v, to)
		return "%" + t, nil
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported arg type %s", to)
	}
}

func (c *arm64Ctx) structArgFromSequentialRegs(aggTy LLVMType, regCursor *int) (string, error) {
	fields, ok := parseLiteralStructFields(aggTy)
	if !ok || !literalFieldsAllScalar(fields) {
		return "", fmt.Errorf("unsupported aggregate arg type %s", aggTy)
	}
	agg := "undef"
	for fi, fty := range fields {
		r := Reg(fmt.Sprintf("R%d", *regCursor))
		*regCursor++
		v, err := c.loadReg(r)
		if err != nil {
			return "", err
		}
		val, err := c.castI64RegToArg(v, fty)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", t, aggTy, agg, fty, val, fi)
		agg = "%" + t
	}
	return agg, nil
}

func (c *arm64Ctx) abi0CallStackPtr(off int64) (string, error) {
	sp, err := c.loadReg(SP)
	if err != nil {
		return "", fmt.Errorf("ABI0 call stack: %w", err)
	}
	// Go's arm64 ABI0 outgoing call frame reserves the first pointer-sized
	// slot for the saved link register. Callee FP offset zero is therefore
	// caller RSP+8, as emitted by the Go compiler before ABI0 wrapper calls.
	const linkSlotSize = int64(8)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", next, sp, off+linkSlotSize)
	addr := "%" + next
	ptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", ptr, addr)
	return "%" + ptr, nil
}

func (c *arm64Ctx) abi0CallArgs(callee string, sig FuncSig) ([]string, error) {
	slotsByArg := make([][]FrameSlot, len(sig.Args))
	for _, slot := range sig.Frame.Params {
		if slot.Index < 0 || slot.Index >= len(sig.Args) {
			return nil, fmt.Errorf("arm64 call %q: ABI0 parameter at +%d has invalid argument index %d", callee, slot.Offset, slot.Index)
		}
		slotsByArg[slot.Index] = append(slotsByArg[slot.Index], slot)
	}
	args := make([]string, 0, len(sig.Args))
	for argIndex, argType := range sig.Args {
		slots := slotsByArg[argIndex]
		if len(slots) == 0 {
			return nil, fmt.Errorf("arm64 call %q: ABI0 argument %d has no frame slot", callee, argIndex)
		}
		if len(slots) == 1 && len(frameSlotFields(slots[0])) == 0 {
			if slots[0].Type != argType {
				return nil, fmt.Errorf("arm64 call %q: ABI0 argument %d frame type %s does not match %s", callee, argIndex, slots[0].Type, argType)
			}
			ptr, err := c.abi0CallStackPtr(slots[0].Offset)
			if err != nil {
				return nil, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, argType, ptr)
			args = append(args, fmt.Sprintf("%s %%%s", argType, value))
			continue
		}
		aggregate := "undef"
		for _, slot := range slots {
			if len(frameSlotFields(slot)) == 0 {
				return nil, fmt.Errorf("arm64 call %q: ABI0 aggregate argument %d has a scalar frame slot", callee, argIndex)
			}
			ptr, err := c.abi0CallStackPtr(slot.Offset)
			if err != nil {
				return nil, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", value, slot.Type, ptr)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %%%s%s\n", inserted, argType, aggregate, slot.Type, value, frameSlotExtractSuffix(slot))
			aggregate = "%" + inserted
		}
		args = append(args, fmt.Sprintf("%s %s", argType, aggregate))
	}
	return args, nil
}

func (c *arm64Ctx) storeABI0CallResult(callee string, sig FuncSig, result string) error {
	if len(sig.Frame.Results) == 0 {
		return fmt.Errorf("arm64 call %q: ABI0 result %s has no frame slot", callee, sig.Ret)
	}
	fields, aggregate := parseLiteralStructFields(sig.Ret)
	for _, slot := range sig.Frame.Results {
		value := result
		if aggregate {
			if slot.Index < 0 || slot.Index >= len(fields) || fields[slot.Index] != slot.Type {
				return fmt.Errorf("arm64 call %q: ABI0 result slot %d does not match %s", callee, slot.Index, sig.Ret)
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", extracted, sig.Ret, result, slot.Index)
			value = "%" + extracted
		} else if slot.Index != 0 || slot.Type != sig.Ret {
			return fmt.Errorf("arm64 call %q: ABI0 scalar result frame does not match %s", callee, sig.Ret)
		}
		ptr, err := c.abi0CallStackPtr(slot.Offset)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", slot.Type, value, ptr)
	}
	return nil
}

func (c *arm64Ctx) callSym(symOp Operand) error {
	if symOp.Kind != OpSym {
		return fmt.Errorf("arm64 call expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm64 call expects (SB) symbol, got %q", s)
	}
	internalABI := strings.HasSuffix(strings.TrimSuffix(s, "(SB)"), "<ABIInternal>")
	s = strings.TrimSuffix(s, "(SB)")
	callee := c.resolve(s)
	// Syscall stubs invoke runtime entersyscall/exitsyscall around SVC.
	// llgo runtime does not require these scheduler hooks at this layer.
	if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
		return nil
	}
	csig, ok := c.sigs[callee]
	if !ok {
		// Default for external runtime helpers not discovered in this asm file.
		csig = FuncSig{Name: callee, Ret: Void}
	}
	callee = funcSigSymbol(callee, csig)
	stackABI := !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) != 0
	var args []string
	if stackABI {
		var err error
		args, err = c.abi0CallArgs(callee, csig)
		if err != nil {
			return err
		}
	} else {
		var err error
		args, err = c.abiRegisterCallArgs(callee, csig)
		if err != nil {
			return err
		}
	}
	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	if !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Results) != 0 {
		return c.storeABI0CallResult(callee, csig, "%"+t)
	}
	return c.storeABIRegisterResult(callee, csig.Ret, "%"+t)
}

func (c *arm64Ctx) tailCallAndRet(symOp Operand) error {
	if symOp.Kind != OpSym {
		return fmt.Errorf("arm64 tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm64 tailcall expects (SB) symbol, got %q", s)
	}
	internalABI := strings.HasSuffix(strings.TrimSuffix(s, "(SB)"), "<ABIInternal>")
	s = strings.TrimSuffix(s, "(SB)")
	callee := c.resolve(s)
	csig, ok := c.sigs[callee]
	if !ok {
		// Cross-package trampoline (e.g. sync/atomic -> internal/runtime/atomic).
		// If we don't have an explicit signature, fall back to caller signature.
		csig = c.sig
		csig.Name = callee
	}
	callee = funcSigSymbol(callee, csig)

	useLLVMArgs := len(csig.ArgRegs) == 0 && len(csig.Args) == len(c.sig.Args) && csig.Ret == c.sig.Ret
	if useLLVMArgs {
		for i := range csig.Args {
			if csig.Args[i] != c.sig.Args[i] {
				useLLVMArgs = false
				break
			}
		}
	}
	args := make([]string, 0, len(csig.Args))
	if useLLVMArgs {
		for i, typ := range csig.Args {
			args = append(args, fmt.Sprintf("%s %%arg%d", typ, i))
		}
	} else if !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) != 0 {
		var err error
		args, err = c.abi0CallArgs(callee, csig)
		if err != nil {
			return fmt.Errorf("arm64 tailcall: %w", err)
		}
	} else {
		var err error
		args, err = c.abiRegisterCallArgs(callee, csig)
		if err != nil {
			return fmt.Errorf("arm64 tailcall: %w", err)
		}
	}

	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		// If caller returns via classic FP result slots, return from those after the call.
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		// Some rt0 stubs tailcall into runtime init entrypoints and don't return.
		// Keep lowering permissive by emitting a zero return when caller has a
		// scalar return type but no explicit FP result slots.
		if c.sig.Ret != Void {
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, llvmZeroValue(c.sig.Ret))
			return nil
		}
		c.b.WriteString("  ret void\n")
		return nil
	}

	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", call, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	if c.sig.Ret == Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	if csig.Ret != c.sig.Ret {
		conv := c.newTmp()
		calleeBits, calleeInteger := armIntegerTypeWidth(csig.Ret)
		callerBits, callerInteger := armIntegerTypeWidth(c.sig.Ret)
		switch {
		case calleeInteger && callerInteger && calleeBits > callerBits:
			fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", conv, csig.Ret, call, c.sig.Ret)
		case calleeInteger && callerInteger && calleeBits < callerBits:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to %s\n", conv, csig.Ret, call, c.sig.Ret)
		case csig.Ret == Ptr && c.sig.Ret == I64:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", conv, call)
		case csig.Ret == I64 && c.sig.Ret == Ptr:
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", conv, call)
		default:
			return fmt.Errorf("arm64 tailcall return mismatch: caller %s callee %s", c.sig.Ret, csig.Ret)
		}
		fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, conv)
		return nil
	}
	fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, call)
	return nil
}
