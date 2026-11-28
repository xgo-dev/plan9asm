package arm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

type armEmitBr func(target string)
type armEmitCondBr func(cond string, target string, fall string) error

func (c *armCtx) lowerBranch(bi int, op, cond string, ins asm.Instr, emitBr armEmitBr, emitCondBr armEmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "JMP":
		op = "B"
	}
	if armIsConditionalBranch(op) && op != "B" {
		cond, op = op[1:], "B"
		switch cond {
		case "CS":
			cond = "HS"
		case "CC":
			cond = "LO"
		}
	}
	if cond == "AL" {
		cond = ""
	}
	switch op {
	case "BL", "CALL":
		if len(ins.Args) != 1 && len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm %s expects 1 operand: %q", op, ins.Raw)
		}
		tgtArg := ins.Args[len(ins.Args)-1]
		emitCall := func() error {
			switch tgtArg.Kind {
			case asm.OpReg:
				addr, err := c.loadReg(tgtArg.Reg)
				if err != nil {
					return err
				}
				fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "blx $0", "r,~{cc},~{memory}", addr)
				c.flagsDef = 0
				c.flagsTouched |= armFlagAll
				return nil
			case asm.OpMem:
				addr, _, _, err := c.addrI32(tgtArg.Mem, false)
				if err != nil {
					return err
				}
				fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "blx $0", "r,~{cc},~{memory}", addr)
				c.flagsDef = 0
				c.flagsTouched |= armFlagAll
				return nil
			case asm.OpSym:
				return c.callSym(tgtArg)
			default:
				return fmt.Errorf("arm %s invalid target: %q", op, ins.Raw)
			}
		}
		if cond != "" {
			return true, false, c.emitConditionalEffect(cond, emitCall)
		}
		return true, false, emitCall()
	case "B":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm B expects 1 operand: %q", ins.Raw)
		}
		if cond != "" && ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			if bi+1 >= len(c.blocks) {
				return true, false, fmt.Errorf("arm B.%s needs a fallthrough block", cond)
			}
			label := "tail_" + c.newTmp()
			if err := emitCondBr(cond, label, c.blocks[bi+1].name); err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "%s:\n", armLLVMBlockName(label))
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		if cond != "" {
			tgt, ok := c.resolveBranchTarget(bi, ins.Args[0])
			if !ok {
				return true, false, fmt.Errorf("arm B.%s invalid target: %q", cond, ins.Raw)
			}
			if bi+1 >= len(c.blocks) {
				return true, false, fmt.Errorf("arm B.%s needs fallthrough block: %q", cond, ins.Raw)
			}
			if err := emitCondBr(cond, tgt, c.blocks[bi+1].name); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		if ins.Args[0].Kind == asm.OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		if ins.Args[0].Kind == asm.OpMem && ins.Args[0].Mem.Base != asm.PC {
			addr, _, _, err := c.addrI32(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "bx $0", "r,~{memory}", addr)
			c.lowerRetZero()
			return true, true, nil
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm B invalid target: %q", ins.Raw)
		}
		emitBr(tgt)
		return true, true, nil

	}
	return false, false, nil
}

func (c *armCtx) castI32RegToArg(v string, to asm.LLVMType) (string, error) {
	switch to {
	case asm.I32:
		return v, nil
	case asm.I16, asm.I8, asm.I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, v, to)
		return "%" + t, nil
	case asm.Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", t, v)
		return "%" + t, nil
	case asm.I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported arg type %s", to)
	}
}

func (c *armCtx) tailCallAndRet(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("arm tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm tailcall expects (SB) symbol, got %q", s)
	}
	callee := c.resolve(strings.TrimSuffix(s, "(SB)"))
	if c.kuserCAS[callee] {
		if err := c.emitKuserCAS(); err != nil {
			return err
		}
		return c.returnRegisters()
	}
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
		r := asm.Reg(fmt.Sprintf("R%d", i))
		if i < len(csig.ArgRegs) {
			r = csig.ArgRegs[i]
		}
		v, err := c.loadReg(r)
		if err != nil {
			return err
		}
		val, err := c.castI32RegToArg(v, csig.Args[i])
		if err != nil {
			return fmt.Errorf("arm tailcall %q unsupported arg type %s", callee, csig.Args[i])
		}
		args = append(args, fmt.Sprintf("%s %s", csig.Args[i], val))
	}
	if csig.Ret == asm.Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", asm.LLVMGlobal(callee), strings.Join(args, ", "))
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		if c.sig.Ret == asm.Void {
			c.b.WriteString("  ret void\n")
			return nil
		}
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, asm.LLVMZeroValue(c.sig.Ret))
		return nil
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
		case csig.Ret == asm.I32 && (c.sig.Ret == asm.I1 || c.sig.Ret == asm.I8 || c.sig.Ret == asm.I16):
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to %s\n", conv, t, c.sig.Ret)
		case (csig.Ret == asm.I1 || csig.Ret == asm.I8 || csig.Ret == asm.I16) && c.sig.Ret == asm.I32:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", conv, csig.Ret, t)
		case csig.Ret == asm.Ptr && c.sig.Ret == asm.I32:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i32\n", conv, t)
		case csig.Ret == asm.I32 && c.sig.Ret == asm.Ptr:
			fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %%%s to ptr\n", conv, t)
		default:
			return fmt.Errorf("arm tailcall return mismatch: caller %s callee %s", c.sig.Ret, csig.Ret)
		}
		fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, conv)
		return nil
	}
	fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, t)
	return nil
}

func (c *armCtx) emitKuserCAS() error {
	// Linux/ARM __kuser_cmpxchg (0xffff0fc0): R0=old, R1=new, R2=ptr =>
	// swaps *ptr atomically, sets C=1 and R0=0 on success (C=0, R0=1 on fail).
	oldV, err := c.loadReg(asm.Reg("R0"))
	if err != nil {
		return err
	}
	newV, err := c.loadReg(asm.Reg("R1"))
	if err != nil {
		return err
	}
	addr, err := c.loadReg(asm.Reg("R2"))
	if err != nil {
		return err
	}
	pt := c.newTmp()
	cx := c.newTmp()
	swapped := c.newTmp()
	failed := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", pt, addr)
	fmt.Fprintf(c.b, "  %%%s = cmpxchg ptr %%%s, i32 %s, i32 %s seq_cst seq_cst, align 4\n", cx, pt, oldV, newV)
	fmt.Fprintf(c.b, "  %%%s = extractvalue {i32, i1} %%%s, 1\n", swapped, cx)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", failed, swapped)
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i32\n", status, failed)
	if err := c.storeReg(asm.Reg("R0"), "%"+status); err != nil {
		return err
	}
	c.storeFlag(c.flagsCSlot, "%"+swapped)
	c.flagsDef = armFlagC
	c.flagsTouched |= armFlagAll
	return nil
}

func (c *armCtx) callSym(symOp asm.Operand) error {
	if symOp.Kind != asm.OpSym {
		return fmt.Errorf("arm call expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm call expects (SB) symbol, got %q", s)
	}
	callee := c.resolve(strings.TrimSuffix(s, "(SB)"))
	if callee == "runtime.entersyscall" || callee == "runtime.exitsyscall" {
		return nil
	}
	if c.kuserCAS[callee] {
		return c.emitKuserCAS()
	}
	csig, ok := c.sigs[callee]
	if !ok {
		csig = asm.FuncSig{Name: callee, Ret: asm.Void}
	}
	callee = asm.FuncSigSymbol(callee, csig)
	args := make([]string, 0, len(csig.Args))
	for i := 0; i < len(csig.Args); i++ {
		r := asm.Reg(fmt.Sprintf("R%d", i))
		if i < len(csig.ArgRegs) {
			r = csig.ArgRegs[i]
		}
		v, err := c.loadReg(r)
		if err != nil {
			return err
		}
		val, err := c.castI32RegToArg(v, csig.Args[i])
		if err != nil {
			return fmt.Errorf("arm call %q unsupported arg type %s", callee, csig.Args[i])
		}
		args = append(args, fmt.Sprintf("%s %s", csig.Args[i], val))
	}
	if csig.Ret == asm.Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", asm.LLVMGlobal(callee), strings.Join(args, ", "))
		c.flagsDef = 0
		c.flagsTouched |= armFlagAll
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, asm.LLVMGlobal(callee), strings.Join(args, ", "))
	c.flagsDef = 0
	c.flagsTouched |= armFlagAll
	switch csig.Ret {
	case asm.I32:
		return c.storeReg(asm.Reg("R0"), "%"+t)
	case asm.I16, asm.I8, asm.I1:
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", z, csig.Ret, t)
		return c.storeReg(asm.Reg("R0"), "%"+z)
	case asm.Ptr:
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i32\n", p, t)
		return c.storeReg(asm.Reg("R0"), "%"+p)
	case asm.I64:
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", tr, t)
		return c.storeReg(asm.Reg("R0"), "%"+tr)
	default:
		return fmt.Errorf("arm call %q unsupported return type %s", callee, csig.Ret)
	}
}

func armIsConditionalBranch(op string) bool {
	switch op {
	case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		return true
	}
	return false
}
