package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) resolveBranchTarget(_ int, op Operand) (string, bool) {
	// Named n(PC) operands must have been normalized to exact source labels.
	// A block index cannot recover their instruction-relative destination.
	return arm64BranchTarget(op)
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
			if err := c.storeLocalLink(c.blocks[bi+1].name); err != nil {
				return true, false, err
			}
			emitBr(target)
			return true, true, nil
		}
		if ins.Args[0].Kind == OpReg || ins.Args[0].Kind == OpMem {
			term, err := c.lowerRegisterControl(bi, op, ins)
			return true, term, err
		}
		if ins.Args[0].Kind != OpSym || !strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, false, fmt.Errorf("arm64 %s expects symbol(SB)|reg|mem: %q", op, ins.Raw)
		}
		if err := c.callSym(ins.Args[0]); err != nil {
			return true, false, err
		}
		if bi+1 < len(c.blocks) {
			if err := c.storeLocalLink(c.blocks[bi+1].name); err != nil {
				return true, false, err
			}
		}
		return true, false, nil

	case "B", "JMP":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 B expects 1 operand: %q", ins.Raw)
		}
		if strings.Contains(string(ins.Op), ".") {
			return true, false, fmt.Errorf("arm64 %s does not accept a suffix: %q", op, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg || ins.Args[0].Kind == OpMem {
			term, err := c.lowerRegisterControl(bi, op, ins)
			return true, term, err
		}
		if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			if c.lowerProvenUnreachableControl(bi) {
				return true, true, nil
			}
			if c.sourceGoFrame.present {
				return true, false, fmt.Errorf("%w: ARM64 symbol branch has no implicit Go frame epilogue: %q", ErrProbeNeedsContext, ins.Raw)
			}
			if err := c.requireCallerSPRestored(bi, ins); err != nil {
				return true, false, err
			}
			if err := c.requireCallerLinkRestored(bi, ins); err != nil {
				return true, false, err
			}
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		tgt, ok := arm64BranchTarget(ins.Args[0])
		if !ok {
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
		if bit < 0 || bit > 63 {
			return true, false, fmt.Errorf("arm64 %s bit index must be in [0, 63]: %q", op, ins.Raw)
		}
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

// This finite lowering contract is not a general native-call effect proof.
// LLGo's syscall bridge elides these scheduler hooks entirely. Its source BL
// still produces the Go continuation/prologue, but no emitted call can observe
// the virtual frame or change its GP/FP contents. Control and availability
// analysis must use the same boundary as callSym, not an unknown native call.
func arm64ElidesSchedulerHook(callee string) bool {
	return callee == "runtime.entersyscall" || callee == "runtime.exitsyscall"
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
	if arm64ElidesSchedulerHook(callee) {
		return nil
	}
	csig, ok := c.sigs[callee]
	if csig.ARM64ClosureABI != nil {
		return arm64GoABIContext("call %q requires a matching typed closure carrier", callee)
	}
	if !ok {
		// Default for external runtime helpers not discovered in this asm file.
		csig = FuncSig{Name: callee, Ret: Void}
	}
	if internalABI {
		if csig.ARM64GoRegisterABI != nil {
			if err := arm64ValidateGoRegisterABI(csig); err != nil {
				return err
			}
		} else if len(csig.ArgRegs) == 0 || len(csig.ArgRegs) != len(csig.Args) {
			return fmt.Errorf("%w: ARM64 ABIInternal call %q requires an explicit complete register-entry contract", ErrProbeNeedsContext, callee)
		}
	}
	callee = funcSigSymbol(callee, csig)
	stackABI := !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) != 0
	var args []string
	if internalABI && csig.ARM64GoRegisterABI != nil {
		var err error
		args, err = c.goABIRegisterCallArgs(csig)
		if err != nil {
			return err
		}
	} else if stackABI {
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
		if internalABI {
			c.recordMachineCall(csig.ARM64GoRegisterABI, s)
		} else {
			c.recordMachineCall(nil, s)
		}
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	if internalABI && csig.ARM64GoRegisterABI != nil {
		if err := c.storeGoABIRegisterResult(csig, "%"+t); err != nil {
			return err
		}
		c.recordMachineCall(csig.ARM64GoRegisterABI, s)
		return nil
	}
	if !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Results) != 0 {
		if err := c.storeABI0CallResult(callee, csig, "%"+t); err != nil {
			return err
		}
		c.recordMachineCall(nil, s)
		return nil
	}
	if err := c.storeABIRegisterResult(callee, csig.Ret, "%"+t); err != nil {
		return err
	}
	c.recordMachineCall(nil, s)
	return nil
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
	if csig.ARM64ClosureABI != nil {
		return arm64GoABIContext("tail call %q requires a matching typed closure carrier", callee)
	}
	if err := arm64ValidatePrivateTailTransport(symOp.Sym, csig, ok); err != nil {
		return err
	}
	if !ok {
		// Cross-package trampoline (e.g. sync/atomic -> internal/runtime/atomic).
		// If we don't have an explicit signature, fall back to caller signature.
		csig = c.sig
		csig.Name = callee
		csig.ARM64GoRegisterABI = nil
	}
	if c.goRegisterEntry && !internalABI && len(csig.ArgRegs) == 0 {
		return arm64GoABIContext("register entry tail to %q needs an explicit target register or cross-ABI frame contract", callee)
	}
	if internalABI {
		if csig.ARM64GoRegisterABI != nil {
			if err := arm64ValidateGoRegisterABI(csig); err != nil {
				return err
			}
		} else if len(csig.ArgRegs) == 0 || len(csig.ArgRegs) != len(csig.Args) {
			return fmt.Errorf("%w: ARM64 ABIInternal tail call %q requires an explicit complete register-entry contract", ErrProbeNeedsContext, callee)
		}
	}
	callee = funcSigSymbol(callee, csig)

	useLLVMArgs := !c.goRegisterEntry && !internalABI && len(csig.ArgRegs) == 0 && len(csig.Args) == len(c.sig.Args) && csig.Ret == c.sig.Ret
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
	} else if internalABI && csig.ARM64GoRegisterABI != nil {
		var err error
		args, err = c.goABIRegisterCallArgs(csig)
		if err != nil {
			return err
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
