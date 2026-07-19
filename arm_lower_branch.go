package plan9asm

import (
	"fmt"
	"strings"
)

type armEmitBr func(target string)
type armEmitCondBr func(cond string, target string, fall string) error

func (c *armCtx) lowerBranch(bi int, op, cond string, ins Instr, emitBr armEmitBr, emitCondBr armEmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "JMP":
		op = "B"
	}
	switch op {
	case "BL", "CALL":
		if cond != "" {
			return true, false, fmt.Errorf("arm %s.%s unsupported: %q", op, cond, ins.Raw)
		}
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm %s expects 1 operand: %q", op, ins.Raw)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "blx $0", "r,~{memory}", addr)
			return true, false, nil
		case OpMem:
			addr, _, _, err := c.addrI32(ins.Args[0].Mem, false)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "blx $0", "r,~{memory}", addr)
			return true, false, nil
		case OpSym:
			return true, false, c.callSym(ins.Args[0])
		default:
			return true, false, fmt.Errorf("arm %s invalid target: %q", op, ins.Raw)
		}
	case "B":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm B expects 1 operand: %q", ins.Raw)
		}
		if cond != "" {
			tgt, ok := armBranchTarget(ins.Args[0])
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
		if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		tgt, ok := armBranchTarget(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm B invalid target: %q", ins.Raw)
		}
		emitBr(tgt)
		return true, true, nil
	case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm %s expects label: %q", op, ins.Raw)
		}
		tgt, ok := armBranchTarget(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("arm %s invalid target: %q", op, ins.Raw)
		}
		if bi+1 >= len(c.blocks) {
			return true, false, fmt.Errorf("arm %s needs fallthrough block: %q", op, ins.Raw)
		}
		branchCond := op[1:]
		if branchCond == "CS" {
			branchCond = "HS"
		}
		if branchCond == "CC" {
			branchCond = "LO"
		}
		if err := emitCondBr(branchCond, tgt, c.blocks[bi+1].name); err != nil {
			return true, false, err
		}
		return true, true, nil
	}
	return false, false, nil
}

func (c *armCtx) castI32RegToArg(v string, to LLVMType) (string, error) {
	switch to {
	case I32:
		return v, nil
	case I16, I8, I1:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to %s\n", t, v, to)
		return "%" + t, nil
	case Ptr:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %s to ptr\n", t, v)
		return "%" + t, nil
	case I64:
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", t, v)
		return "%" + t, nil
	default:
		return "", fmt.Errorf("unsupported arg type %s", to)
	}
}

func (c *armCtx) tailCallAndRet(symOp Operand) error {
	if symOp.Kind != OpSym {
		return fmt.Errorf("arm tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("arm tailcall expects (SB) symbol, got %q", s)
	}
	callee := c.resolve(strings.TrimSuffix(s, "(SB)"))
	csig, ok := c.sigs[callee]
	if !ok {
		return fmt.Errorf("arm tailcall missing signature for %q", callee)
	}
	callee = funcSigSymbol(callee, csig)
	args := make([]string, 0, len(csig.Args))
	for i := 0; i < len(csig.Args); i++ {
		r := Reg(fmt.Sprintf("R%d", i))
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
	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		if c.sig.Ret == Void {
			c.b.WriteString("  ret void\n")
			return nil
		}
		fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, llvmZeroValue(c.sig.Ret))
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	if c.sig.Ret != csig.Ret {
		return fmt.Errorf("arm tailcall return mismatch: caller %s callee %s", c.sig.Ret, csig.Ret)
	}
	fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, t)
	return nil
}

func (c *armCtx) callSym(symOp Operand) error {
	if symOp.Kind != OpSym {
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
	csig, ok := c.sigs[callee]
	if !ok {
		csig = FuncSig{Name: callee, Ret: Void}
	}
	callee = funcSigSymbol(callee, csig)
	args := make([]string, 0, len(csig.Args))
	for i := 0; i < len(csig.Args); i++ {
		r := Reg(fmt.Sprintf("R%d", i))
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
	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	switch csig.Ret {
	case I32:
		return c.storeReg(Reg("R0"), "%"+t)
	case I16, I8, I1:
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", z, csig.Ret, t)
		return c.storeReg(Reg("R0"), "%"+z)
	case Ptr:
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i32\n", p, t)
		return c.storeReg(Reg("R0"), "%"+p)
	case I64:
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", tr, t)
		return c.storeReg(Reg("R0"), "%"+tr)
	default:
		return fmt.Errorf("arm call %q unsupported return type %s", callee, csig.Ret)
	}
}
