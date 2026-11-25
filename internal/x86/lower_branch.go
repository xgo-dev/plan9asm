package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func (c *amd64Ctx) lowerBranch(bi int, ii int, op asm.Op, ins asm.Instr, emitBr amd64EmitBr, emitCondBr amd64EmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "CALL":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 CALL expects 1 operand: %q", ins.Raw)
		}
		switch ins.Args[0].Kind {
		case asm.OpReg:
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			if err := c.callIndirectAddr(addr); err != nil {
				return true, false, err
			}
			return true, false, nil
		case asm.OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fnptr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", fnptr, p)
			if err := c.callIndirectAddr("%" + fnptr); err != nil {
				return true, false, err
			}
			return true, false, nil
		case asm.OpSym:
			if err := c.callSym(ins.Args[0]); err != nil {
				return true, false, err
			}
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 CALL expects reg or symbol(SB) target: %q", ins.Raw)
		}

	case "JMP",
		"JE", "JEQ", "JZ", "JNE", "JNZ",
		"JL", "JLT", "JLE", "JG", "JGT", "JGE", "JS", "JNS",
		"JA", "JHI", "JAE", "JHS", "JB", "JLO", "JBE", "JLS", "JNA",
		"JC", "JNC", "JCC":
		// ok
	default:
		return false, false, nil
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("amd64 %s expects 1 operand: %q", op, ins.Raw)
	}
	target := ""
	pcRel := false
	pcOff := int64(0)
	knownBlock := func(name string) bool {
		for _, blk := range c.blocks {
			if blk.name == name {
				return true
			}
		}
		return false
	}
	switch ins.Args[0].Kind {
	case asm.OpIdent:
		target = ins.Args[0].Ident
	case asm.OpReg:
		// Labels like V1 may be tokenized as registers. Prefer block labels;
		// otherwise treat JMP reg as an indirect tail jump.
		name := string(ins.Args[0].Reg)
		if knownBlock(name) {
			target = name
			break
		}
		if op == "JMP" {
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			if err := c.tailCallIndirectAddrAndRet(addr); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		return true, false, fmt.Errorf("amd64 %s invalid register target: %q", op, ins.Raw)
	case asm.OpSym:
		s := strings.TrimSpace(ins.Args[0].Sym)
		// Treat JMP foo(SB) as a tailcall to another TEXT (common in stdlib asm).
		if op == "JMP" && strings.HasSuffix(s, "(SB)") {
			if err := c.tailCallAndRet(ins.Args[0]); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		// Local labels sometimes appear with "<>" or (SB) suffix.
		s = strings.TrimSuffix(strings.TrimSuffix(s, "(SB)"), "<>")
		target = s
	case asm.OpMem:
		// PC-relative branches like "JEQ 2(PC)" are used as a compact way to skip
		// the next instruction. Handle them by mapping the offset to our block
		// sequence (blocks are split at terminators, so the pattern works well).
		if strings.EqualFold(string(ins.Args[0].Mem.Base), "PC") {
			pcRel = true
			pcOff = ins.Args[0].Mem.Off
			break
		}
		if op == "JMP" {
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			fnptr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", fnptr, p)
			if err := c.tailCallIndirectAddrAndRet("%" + fnptr); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		fallthrough
	case asm.OpImm:
		if op == "JMP" {
			if err := c.tailCallIndirectAddrAndRet(fmt.Sprintf("%d", ins.Args[0].Imm)); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		return true, false, fmt.Errorf("amd64 %s invalid target: %q", op, ins.Raw)
	default:
		return true, false, fmt.Errorf("amd64 %s invalid target: %q", op, ins.Raw)
	}
	if !pcRel && target == "" {
		return true, false, fmt.Errorf("amd64 %s empty target: %q", op, ins.Raw)
	}
	if pcRel {
		cur := c.blockBase[bi] + ii
		tgt := cur + int(pcOff)
		tbi, ok := c.blockByIdx[tgt]
		if !ok || tbi < 0 || tbi >= len(c.blocks) {
			return true, false, fmt.Errorf("amd64 %s invalid PC-relative target %d(PC): %q", op, pcOff, ins.Raw)
		}
		target = c.blocks[tbi].name
	}

	if op == "JMP" {
		emitBr(target)
		return true, true, nil
	}

	// Conditional branch: fallthrough to the next basic block.
	if bi+1 >= len(c.blocks) {
		return true, false, fmt.Errorf("amd64 %s has no fallthrough block: %q", op, ins.Raw)
	}
	fall := c.blocks[bi+1].name
	cond := ""
	switch op {
	case "JE", "JEQ", "JZ":
		cond = c.loadFlag(c.flagsZSlot)
	case "JNE", "JNZ":
		z := c.loadFlag(c.flagsZSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, z)
		cond = "%" + t
	case "JL", "JLT":
		cond = c.loadFlag(c.flagsSltSlot)
	case "JGE":
		slt := c.loadFlag(c.flagsSltSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, slt)
		cond = "%" + t
	case "JS":
		cond = c.loadFlag(c.flagsSltSlot)
	case "JNS":
		slt := c.loadFlag(c.flagsSltSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, slt)
		cond = "%" + t
	case "JLE":
		slt := c.loadFlag(c.flagsSltSlot)
		z := c.loadFlag(c.flagsZSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, slt, z)
		cond = "%" + t
	case "JG", "JGT":
		slt := c.loadFlag(c.flagsSltSlot)
		z := c.loadFlag(c.flagsZSlot)
		t1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, slt, z)
		t2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
		cond = "%" + t2
	case "JB", "JLO", "JC":
		cond = c.loadFlag(c.flagsCFSlot)
	case "JNC", "JCC":
		cf := c.loadFlag(c.flagsCFSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, cf)
		cond = "%" + t
	case "JAE", "JHS":
		cf := c.loadFlag(c.flagsCFSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", t, cf)
		cond = "%" + t
	case "JBE", "JLS", "JNA":
		cf := c.loadFlag(c.flagsCFSlot)
		z := c.loadFlag(c.flagsZSlot)
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, cf, z)
		cond = "%" + t
	case "JA", "JHI":
		cf := c.loadFlag(c.flagsCFSlot)
		z := c.loadFlag(c.flagsZSlot)
		t1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, cf, z)
		t2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
		cond = "%" + t2
	default:
		return true, false, fmt.Errorf("amd64: unsupported branch %s", op)
	}

	if err := emitCondBr(cond, target, fall); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func (c *amd64Ctx) callIndirectAddr(addr string) error {
	fptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", fptr, addr)
	di, _ := c.loadReg(asm.DI)
	si, _ := c.loadReg(asm.SI)
	dx, _ := c.loadReg(asm.DX)
	cx, _ := c.loadReg(asm.CX)
	r8, _ := c.loadReg(asm.Reg("R8"))
	r9, _ := c.loadReg(asm.Reg("R9"))
	ret := c.newTmp()
	// Model as a generic C-ABI style call carrying register arguments.
	fmt.Fprintf(c.b, "  %%%s = call i64 %%%s(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n", ret, fptr, di, si, dx, cx, r8, r9)
	return c.storeReg(asm.AX, "%"+ret)
}

func (c *amd64Ctx) tailCallIndirectAddrAndRet(addr string) error {
	if err := c.callIndirectAddr(addr); err != nil {
		return err
	}
	return c.lowerRET()
}

func (c *amd64Ctx) castI64RegToArg(v string, to asm.LLVMType) (string, error) {
	switch to {
	case asm.I64:
		return v, nil
	case asm.I1, asm.I8, asm.I16, asm.I32:
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

func (c *amd64Ctx) structArgFromSequentialRegs(aggTy asm.LLVMType, regs []asm.Reg, regCursor *int) (string, error) {
	fields, ok := asm.ParseLiteralStructFields(aggTy)
	if !ok || !asm.LiteralFieldsAllScalar(fields) {
		return "", fmt.Errorf("unsupported aggregate arg type %s", aggTy)
	}
	agg := "undef"
	for fi, fieldTy := range fields {
		if *regCursor >= len(regs) {
			return "", fmt.Errorf("aggregate arg %s exceeds integer argument registers", aggTy)
		}
		value, err := c.loadReg(regs[*regCursor])
		*regCursor = *regCursor + 1
		if err != nil {
			return "", err
		}
		field, err := c.castI64RegToArg(value, fieldTy)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", t, aggTy, agg, fieldTy, field, fi)
		agg = "%" + t
	}
	return agg, nil
}

func (c *amd64Ctx) callSym(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("amd64 call expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("amd64 call expects (SB) symbol, got %q", s)
	}
	if base, off, ok := asm.ParseSBRef(s); ok && base != "" && off != 0 {
		p, err := c.ptrFromSB(s)
		if err != nil {
			return err
		}
		addr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", addr, p)
		return c.callIndirectAddr("%" + addr)
	}
	s = strings.TrimSuffix(s, "(SB)")
	callee := c.resolve(s)
	// Syscall stubs invoke runtime entersyscall/exitsyscall around SYSCALL.
	// llgo runtime does not require these scheduler hooks at this layer.
	if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
		return nil
	}

	csig, ok := c.sigs[callee]
	if !ok {
		// Keep behavior explicit: cross-symbol CALL needs a signature unless it is
		// a known no-op runtime scheduler hook above.
		return fmt.Errorf("amd64 call missing signature for %q", callee)
	}
	callee = asm.FuncSigSymbol(callee, csig)

	args := make([]string, 0, len(csig.Args))
	useStackABI0 := c.goarch == "amd64" && c.localStackSlot != "" && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) > 0 && c.hasOutgoingSPArgs()
	if useStackABI0 {
		spVal, err := c.loadReg(asm.SP)
		if err != nil {
			return err
		}
		loadFromSP := func(off int64, ty asm.LLVMType) (string, error) {
			addr := spVal
			if off != 0 {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", a, spVal, off)
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
						return fmt.Errorf("amd64 ABI0 call %q: missing frame slot for arg %d field %d", callee, i, fi)
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
				return fmt.Errorf("amd64 ABI0 call %q: missing frame slot for arg %d", callee, i)
			}
			v, err := loadFromSP(slotOff, argTy)
			if err != nil {
				return err
			}
			args = append(args, fmt.Sprintf("%s %s", argTy, v))
		}
	} else {
		goABI := []asm.Reg{asm.AX, asm.BX, asm.CX, asm.DI, asm.SI, asm.Reg("R8"), asm.Reg("R9"), asm.Reg("R10"), asm.Reg("R11")}
		regCursor := 0
		for i, argTy := range csig.Args {
			if len(csig.ArgRegs) == 0 {
				if fields, ok := asm.ParseLiteralStructFields(argTy); ok && asm.LiteralFieldsAllScalar(fields) {
					agg, err := c.structArgFromSequentialRegs(argTy, goABI, &regCursor)
					if err != nil {
						return fmt.Errorf("amd64 call %q: %w", callee, err)
					}
					args = append(args, fmt.Sprintf("%s %s", argTy, agg))
					continue
				}
			}

			var r asm.Reg
			if len(csig.ArgRegs) > 0 {
				if i >= len(csig.ArgRegs) {
					return fmt.Errorf("amd64 call: missing arg reg for %q arg %d", callee, i)
				}
				r = csig.ArgRegs[i]
			} else {
				if regCursor >= len(goABI) {
					return fmt.Errorf("amd64 call: missing arg reg for %q arg %d", callee, i)
				}
				r = goABI[regCursor]
				regCursor++
			}
			v, err := c.loadReg(r)
			if err != nil {
				return err
			}
			value, err := c.castI64RegToArg(v, argTy)
			if err != nil {
				return fmt.Errorf("amd64 call unsupported arg type %q", argTy)
			}
			args = append(args, fmt.Sprintf("%s %s", argTy, value))
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
		storeToSP := func(off int64, ty asm.LLVMType, val string) {
			addr := spVal
			if off != 0 {
				a := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", a, spVal, off)
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
		return c.storeReg(asm.AX, "%"+t)
	case asm.I1, asm.I8, asm.I16, asm.I32:
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, csig.Ret, t)
		return c.storeReg(asm.AX, "%"+z)
	case asm.Ptr:
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", p, t)
		return c.storeReg(asm.AX, "%"+p)
	default:
		fields, ok := asm.ParseLiteralStructFields(csig.Ret)
		if !ok || !asm.LiteralFieldsAllScalar(fields) {
			return fmt.Errorf("amd64 call %q unsupported return type %s", callee, csig.Ret)
		}
		resultRegs := []asm.Reg{asm.AX, asm.BX, asm.CX, asm.DI, asm.SI, asm.Reg("R8"), asm.Reg("R9"), asm.Reg("R10"), asm.Reg("R11")}
		if len(fields) > len(resultRegs) {
			return fmt.Errorf("amd64 call %q has %d scalar return fields, maximum is %d", callee, len(fields), len(resultRegs))
		}
		for i, fieldTy := range fields {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", extracted, csig.Ret, t, i)
			value, scalar, err := amd64ValueAsI64(c, fieldTy, "%"+extracted)
			if err != nil {
				return err
			}
			if !scalar {
				return fmt.Errorf("amd64 call %q unsupported return field type %s", callee, fieldTy)
			}
			if err := c.storeReg(resultRegs[i], value); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *amd64Ctx) tailCallAndRet(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("amd64 tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("amd64 tailcall expects (SB) symbol, got %q", s)
	}
	if base, off, ok := asm.ParseSBRef(s); ok && base != "" && off != 0 {
		p, err := c.ptrFromSB(s)
		if err != nil {
			return err
		}
		addr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", addr, p)
		return c.tailCallIndirectAddrAndRet("%" + addr)
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
	for i := 0; i < len(csig.Args); i++ {
		// If ArgRegs is empty, default to register-based passing (ABIInternal-ish)
		// because most intra-asm tailcalls depend on explicit register setup.
		//
		// Exception: for tailcalls to Go functions with an identical signature,
		// use the current function's LLVM args. This matches stdlib patterns like
		// "JMP ·countGeneric(SB)" that happen before any register shuffling and
		// are stack-ABI tailcalls in the original asm.
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
				return fmt.Errorf("amd64 tailcall %q: need %d args, caller has %d", callee, len(csig.Args), len(c.sig.Args))
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
				args = append(args, fmt.Sprintf("i64 %%%s", t))
			case fromTy == asm.I64 && toTy == asm.Ptr:
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, fromVal)
				args = append(args, fmt.Sprintf("ptr %%%s", t))
			case fromTy == asm.Ptr && toTy == asm.I64:
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, fromVal)
				args = append(args, fmt.Sprintf("i64 %%%s", t))
			default:
				return fmt.Errorf("amd64 tailcall %q: unsupported arg cast %s -> %s", callee, fromTy, toTy)
			}
			continue
		}

		r := asm.Reg("")
		if i < len(csig.ArgRegs) {
			r = csig.ArgRegs[i]
		} else {
			// Default SysV-ish register order: DI, SI, DX, CX, R8, R9.
			x86 := []asm.Reg{asm.DI, asm.SI, asm.DX, asm.CX, asm.Reg("R8"), asm.Reg("R9")}
			if i >= len(x86) {
				return fmt.Errorf("amd64 tailcall: missing arg reg for %q arg %d", callee, i)
			}
			r = x86[i]
		}
		v, err := c.loadReg(r)
		if err != nil {
			return err
		}
		switch csig.Args[i] {
		case asm.I64:
			args = append(args, "i64 "+v)
		case asm.I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, v)
			args = append(args, "i1 %"+t)
		case asm.I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, v)
			args = append(args, "i8 %"+t)
		case asm.I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, v)
			args = append(args, "i16 %"+t)
		case asm.I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
			args = append(args, "i32 %"+t)
		case asm.Ptr:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
			args = append(args, "ptr %"+t)
		default:
			return fmt.Errorf("amd64 tailcall unsupported arg type %q", csig.Args[i])
		}
	}

	if csig.Ret == asm.Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", asm.LLVMGlobal(callee), strings.Join(args, ", "))
		// If caller returns via classic FP result slots, return from those after the call.
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		if c.sig.Ret == asm.Void {
			c.b.WriteString("  ret void\n")
			return nil
		}
		return fmt.Errorf("amd64 tailcall to %q returns void but caller expects %s", callee, c.sig.Ret)
	}

	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, asm.LLVMGlobal(callee), strings.Join(args, ", "))
	if c.sig.Ret == asm.Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	if c.sig.Ret != csig.Ret {
		conv := c.newTmp()
		switch {
		case csig.Ret == asm.I64 && (c.sig.Ret == asm.I1 || c.sig.Ret == asm.I8 || c.sig.Ret == asm.I16 || c.sig.Ret == asm.I32):
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", conv, t, c.sig.Ret)
			fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, conv)
			return nil
		case (csig.Ret == asm.I1 || csig.Ret == asm.I8 || csig.Ret == asm.I16 || csig.Ret == asm.I32) && c.sig.Ret == asm.I64:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", conv, csig.Ret, t)
			fmt.Fprintf(c.b, "  ret i64 %%%s\n", conv)
			return nil
		case csig.Ret == asm.Ptr && c.sig.Ret == asm.I64:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", conv, t)
			fmt.Fprintf(c.b, "  ret i64 %%%s\n", conv)
			return nil
		case csig.Ret == asm.I64 && c.sig.Ret == asm.Ptr:
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to ptr\n", conv, t)
			fmt.Fprintf(c.b, "  ret ptr %%%s\n", conv)
			return nil
		default:
			return fmt.Errorf("amd64 tailcall return type mismatch for %q: caller %s, callee %s", callee, c.sig.Ret, csig.Ret)
		}
	}
	fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, t)
	return nil
}
