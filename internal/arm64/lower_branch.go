package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *arm64Ctx) resolveBranchTarget(bi int, op asm.Operand) (string, bool) {
	if tgt, ok := arm64BranchTarget(op); ok {
		return tgt, true
	}
	if op.Kind == asm.OpMem && op.Mem.Base == asm.PC && bi >= 0 && bi < len(c.blocks) {
		block := c.blocks[bi]
		dest := block.startPC + int64(len(block.instrs)) - 1 + op.Mem.Off
		for _, b := range c.blocks {
			if len(b.instrs) != 0 && b.startPC == dest {
				return b.name, true
			}
		}
	}
	return "", false
}

func (c *arm64Ctx) lowerBranch(bi int, op asm.Op, ins asm.Instr, emitBr arm64EmitBr, emitCondBr arm64EmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "BL", "BLR", "CALL":
		if c.flagFlow != nil {
			c.flagFlow.clobbers = true
			c.flagsDefined = 0
		}
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 %s expects 1 operand: %q", op, ins.Raw)
		}
		if ins.Args[0].Kind == asm.OpReg {
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "blr $0", "r,~{memory}", addr)
			return true, false, nil
		}
		if ins.Args[0].Kind == asm.OpMem && ins.Args[0].Mem.Base != asm.PC {
			addr, _, _, err := c.addrI64(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "blr $0", "r,~{memory}", addr)
			return true, false, nil
		}
		if ins.Args[0].Kind != asm.OpSym || !strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
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
		if ins.Args[0].Kind == asm.OpReg {
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "br $0", "r,~{memory}", addr)
			c.lowerRetZero()
			return true, true, nil
		}
		if ins.Args[0].Kind == asm.OpMem && ins.Args[0].Mem.Base != asm.PC {
			addr, _, _, err := c.addrI64(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i64 %s)\n", "br $0", "r,~{memory}", addr)
			c.lowerRetZero()
			return true, true, nil
		}
		if ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm64 B invalid target: %q", ins.Raw)
		}
		emitBr(tgt)
		return true, true, nil

	case "BEQ", "BNE", "BLO", "BLT", "BHI", "BHS", "BLS", "BGE", "BGT", "BLE", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 %s expects label: %q", op, ins.Raw)
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[0])
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
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg {
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
		c.branchIf("%"+t, tgt, fall)
		return true, true, nil

	case "TBZ", "TBNZ":
		if len(ins.Args) != 3 || ins.Args[0].Kind != asm.OpImm || ins.Args[1].Kind != asm.OpReg {
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
		c.branchIf("%"+condT, tgt, fall)
		return true, true, nil

	case "CBZW", "CBNZW":
		if len(ins.Args) != 2 || ins.Args[0].Kind != asm.OpReg {
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
		c.branchIf("%"+t, tgt, fall)
		return true, true, nil
	}
	return false, false, nil
}

func (c *arm64Ctx) castI64RegToArg(v string, to asm.LLVMType) (string, error) {
	switch to {
	case asm.I64:
		return v, nil
	case asm.I32, asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v, to)
		return "%" + t, nil
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported arg type %s", to)
	}
}

func (c *arm64Ctx) structArgFromSequentialRegs(aggTy asm.LLVMType, regCursor *int) (string, error) {
	fields, ok := asm.ParseLiteralStructFields(aggTy)
	if !ok || !asm.LiteralFieldsAllScalar(fields) {
		return "", fmt.Errorf("unsupported aggregate arg type %s", aggTy)
	}
	agg := "undef"
	for fi, fty := range fields {
		r := asm.Reg(fmt.Sprintf("R%d", *regCursor))
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

func (c *arm64Ctx) callSym(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("arm64 call expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm64 call expects (SB) symbol, got %q", s)
	}
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
		csig = asm.FuncSig{Name: callee, Ret: asm.Void}
	}
	callee = asm.FuncSigSymbol(callee, csig)
	args := make([]string, 0, len(csig.Args))
	useStackABI0 := c.localStackSlot != "" && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) > 0 && c.hasOutgoingSPArgs()
	if useStackABI0 {
		spVal, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		// On ARM64 Go ABI0, 0(RSP) holds the saved link register, so outgoing
		// stack arguments and results begin at 8(RSP) + slot.Offset.
		const arm64LRSlotSize = int64(8)
		loadFromSP := func(off int64, ty asm.LLVMType) (string, error) {
			addr := spVal
			if totalOff := arm64LRSlotSize + off; totalOff != 0 {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", a, spVal, totalOff)
				addr = "%" + a
			}
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
			v := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %%%s, align 1\n", v, ty, p)
			return "%" + v, nil
		}
		for i, argTy := range csig.Args {
			if fields, ok := asm.ParseLiteralStructFields(argTy); ok && asm.LiteralFieldsAllScalar(fields) {
				cur := "undef"
				for fi, fTy := range fields {
					var slotOff int64
					found := false
					for _, slot := range csig.Frame.Params {
						if slot.Index == i && slot.Field == fi {
							slotOff, found = slot.Offset, true
							break
						}
					}
					if !found {
						return fmt.Errorf("arm64 ABI0 call %q: missing frame slot for arg %d field %d", callee, i, fi)
					}
					fv, err := loadFromSP(slotOff, fTy)
					if err != nil {
						return err
					}
					next := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", next, argTy, cur, fTy, fv, fi)
					cur = "%" + next
				}
				args = append(args, fmt.Sprintf("%s %s", argTy, cur))
				continue
			}
			var slotOff int64
			found := false
			for _, slot := range csig.Frame.Params {
				if slot.Index == i && slot.Field < 0 {
					slotOff, found = slot.Offset, true
					break
				}
			}
			if !found {
				return fmt.Errorf("arm64 ABI0 call %q: missing frame slot for arg %d", callee, i)
			}
			v, err := loadFromSP(slotOff, argTy)
			if err != nil {
				return err
			}
			args = append(args, fmt.Sprintf("%s %s", argTy, v))
		}
	} else {
		regCursor := 0
		for i := 0; i < len(csig.Args); i++ {
			argTy := csig.Args[i]
			if len(csig.ArgRegs) == 0 {
				if fields, ok := asm.ParseLiteralStructFields(argTy); ok && asm.LiteralFieldsAllScalar(fields) {
					agg, err := c.structArgFromSequentialRegs(argTy, &regCursor)
					if err != nil {
						return fmt.Errorf("arm64 call %q: %w", callee, err)
					}
					args = append(args, fmt.Sprintf("%s %s", argTy, agg))
					continue
				}
			}

			r := asm.Reg("")
			if len(csig.ArgRegs) > 0 {
				r = asm.Reg(fmt.Sprintf("R%d", i))
				if i < len(csig.ArgRegs) {
					r = csig.ArgRegs[i]
				}
			} else {
				r = asm.Reg(fmt.Sprintf("R%d", regCursor))
				regCursor++
			}
			v, err := c.loadReg(r)
			if err != nil {
				return err
			}
			val, err := c.castI64RegToArg(v, argTy)
			if err != nil {
				return fmt.Errorf("arm64 call %q unsupported arg type %s", callee, argTy)
			}
			args = append(args, fmt.Sprintf("%s %s", argTy, val))
		}
	}
	if csig.Ret == asm.Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", asm.LLVMGlobal(callee), strings.Join(args, ", "))
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, asm.LLVMGlobal(callee), strings.Join(args, ", "))
	if useStackABI0 && len(csig.Frame.Results) > 0 {
		spVal, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		const arm64LRSlotSize = int64(8)
		storeToSP := func(off int64, ty asm.LLVMType, val string) {
			addr := spVal
			if totalOff := arm64LRSlotSize + off; totalOff != 0 {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", a, spVal, totalOff)
				addr = "%" + a
			}
			p := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", p, addr)
			fmt.Fprintf(c.b, "  store %s %s, ptr %%%s, align 1\n", ty, val, p)
		}
		if len(csig.Frame.Results) == 1 && csig.Frame.Results[0].Field < 0 {
			storeToSP(csig.Frame.Results[0].Offset, csig.Frame.Results[0].Type, "%"+t)
		} else {
			for _, rs := range csig.Frame.Results {
				ex := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", ex, csig.Ret, t, rs.Index)
				val := "%" + ex
				if rs.Field >= 0 {
					ex2 := c.newTmp()
					fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", ex2, rs.Type, val, rs.Field)
					val = "%" + ex2
				}
				storeToSP(rs.Offset, rs.Type, val)
			}
		}
	}
	switch csig.Ret {
	case asm.I64:
		return c.storeReg(asm.Reg("R0"), "%"+t)
	case asm.I32, asm.I16, asm.I8, asm.I1:
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, csig.Ret, t)
		return c.storeReg(asm.Reg("R0"), "%"+z)
	case asm.Ptr:
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", p, t)
		return c.storeReg(asm.Reg("R0"), "%"+p)
	default:
		fields, ok := asm.ParseLiteralStructFields(csig.Ret)
		if !ok || !asm.LiteralFieldsAllScalar(fields) {
			return fmt.Errorf("arm64 call %q unsupported return type %s", callee, csig.Ret)
		}
		for i, fieldTy := range fields {
			if i >= 8 {
				return fmt.Errorf("arm64 call %q has %d scalar return fields, maximum is 8", callee, len(fields))
			}
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", extracted, csig.Ret, t, i)
			value, scalar, err := arm64ValueAsI64(c, fieldTy, "%"+extracted)
			if err != nil {
				return err
			}
			if !scalar {
				return fmt.Errorf("arm64 call %q unsupported return field type %s", callee, fieldTy)
			}
			if err := c.storeReg(asm.Reg(fmt.Sprintf("R%d", i)), value); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *arm64Ctx) tailCallAndRet(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("arm64 tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm64 tailcall expects (SB) symbol, got %q", s)
	}
	s = strings.TrimSuffix(s, "(SB)")
	callee := c.resolve(s)
	csig, ok := c.sigs[callee]
	if !ok {
		// Cross-package trampoline (e.g. sync/atomic -> internal/runtime/atomic).
		// If we don't have an explicit signature, fall back to caller signature.
		csig = c.sig
		csig.Name = callee
	}
	callee = asm.FuncSigSymbol(callee, csig)

	args := make([]string, 0, len(csig.Args))
	regCursor := 0
	for i := 0; i < len(csig.Args); i++ {
		// If ArgRegs is empty, default to register-based passing (ABIInternal-ish)
		// because most intra-asm tailcalls depend on explicit register setup.
		//
		// Exception: for tailcalls to Go functions with an identical signature,
		// use the current function's LLVM args. This matches stdlib patterns like
		// "B ·fooGeneric(SB)" that happen before any register shuffling and are
		// stack-ABI tailcalls in the original asm.
		useLLVMArgs := false
		if len(csig.ArgRegs) == 0 && len(csig.Args) == len(c.sig.Args) && csig.Ret == c.sig.Ret {
			same := true
			for j := 0; j < len(csig.Args); j++ {
				if csig.Args[j] != c.sig.Args[j] {
					same = false
					break
				}
			}
			useLLVMArgs = same
		}
		if useLLVMArgs {
			if i >= len(c.sig.Args) {
				return fmt.Errorf("arm64 tailcall %q: need %d args, caller has %d", callee, len(csig.Args), len(c.sig.Args))
			}
			fromTy := c.sig.Args[i]
			fromVal := fmt.Sprintf("%%arg%d", i)
			toTy := csig.Args[i]
			if fromTy == toTy {
				args = append(args, fmt.Sprintf("%s %s", toTy, fromVal))
				continue
			}
			t := c.newTmp()
			switch {
			case fromTy == asm.I64 && (toTy == asm.I1 || toTy == asm.I8 || toTy == asm.I16 || toTy == asm.I32):
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, fromVal, toTy)
				args = append(args, fmt.Sprintf("%s %%%s", toTy, t))
			case (fromTy == asm.I1 || fromTy == asm.I8 || fromTy == asm.I16 || fromTy == asm.I32) && toTy == asm.I64:
				fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, fromTy, fromVal)
				args = append(args, "i64 %"+t)
			case fromTy == asm.I64 && toTy == asm.Ptr:
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, fromVal)
				args = append(args, "ptr %"+t)
			case fromTy == asm.Ptr && toTy == asm.I64:
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, fromVal)
				args = append(args, "i64 %"+t)
			default:
				return fmt.Errorf("arm64 tailcall %q: unsupported arg cast %s -> %s", callee, fromTy, toTy)
			}
			continue
		}

		if len(csig.ArgRegs) == 0 {
			if fields, ok := asm.ParseLiteralStructFields(csig.Args[i]); ok && asm.LiteralFieldsAllScalar(fields) {
				agg, err := c.structArgFromSequentialRegs(csig.Args[i], &regCursor)
				if err != nil {
					return fmt.Errorf("arm64 tailcall %q: %w", callee, err)
				}
				args = append(args, fmt.Sprintf("%s %s", csig.Args[i], agg))
				continue
			}
		}

		r := asm.Reg("")
		if i < len(csig.ArgRegs) {
			r = csig.ArgRegs[i]
		} else {
			r = asm.Reg(fmt.Sprintf("R%d", regCursor))
			regCursor++
		}
		v, err := c.loadReg(r)
		if err != nil {
			return err
		}
		val, err := c.castI64RegToArg(v, csig.Args[i])
		if err != nil {
			return fmt.Errorf("arm64 tailcall unsupported arg type %q", csig.Args[i])
		}
		args = append(args, fmt.Sprintf("%s %s", csig.Args[i], val))
	}

	if csig.Ret == asm.Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", asm.LLVMGlobal(callee), strings.Join(args, ", "))
		// If caller returns via classic FP result slots, return from those after the call.
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		// Some rt0 stubs tailcall into runtime init entrypoints and don't return.
		// Keep lowering permissive by emitting a zero return when caller has a
		// scalar return type but no explicit FP result slots.
		if c.sig.Ret != asm.Void {
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, asm.LLVMZeroValue(c.sig.Ret))
			return nil
		}
		c.b.WriteString("  ret void\n")
		return nil
	}

	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", call, csig.Ret, asm.LLVMGlobal(callee), strings.Join(args, ", "))
	if c.sig.Ret == asm.Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	if csig.Ret != c.sig.Ret {
		return fmt.Errorf("arm64 tailcall return mismatch: caller %s callee %s", c.sig.Ret, csig.Ret)
	}
	fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, call)
	return nil
}
