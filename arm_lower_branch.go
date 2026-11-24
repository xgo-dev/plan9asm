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
	case "BX":
		register, err := armBranchExchangeTarget(ins)
		if err != nil {
			return true, false, err
		}
		return true, false, c.emitConditionalEffect(cond, func() error {
			return c.emitBranchExchange(register)
		})
	}
	switch op {
	case "BL", "CALL":
		register, indirect, err := armIndirectCallRegister(ins)
		if err != nil {
			return true, false, err
		}
		emitCall := func() error {
			if indirect {
				return c.emitIndirectCall(register)
			}
			if ins.Args[0].Kind == OpSym {
				return c.callSym(ins.Args[0])
			}
			return fmt.Errorf("arm %s invalid target: %q", op, ins.Raw)
		}
		if cond != "" {
			return true, false, c.emitConditionalEffect(cond, emitCall)
		}
		return true, false, emitCall()
	case "B":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm B expects 1 operand: %q", ins.Raw)
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
		if ins.Args[0].Kind == OpSym && strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
			return true, true, c.tailCallAndRet(ins.Args[0])
		}
		if ins.Args[0].Kind == OpMem && ins.Args[0].Mem.Base != PC {
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
	case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm %s expects label: %q", op, ins.Raw)
		}
		tgt, ok := c.resolveBranchTarget(bi, ins.Args[0])
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

func armIndirectCallRegister(ins Instr) (Reg, bool, error) {
	bad := func() (Reg, bool, error) {
		return "", false, fmt.Errorf("arm indirect call expects (register) with zero displacement: %q", ins.Raw)
	}
	if len(ins.Args) != 1 && len(ins.Args) != 2 {
		return bad()
	}
	target := ins.Args[len(ins.Args)-1]
	if len(ins.Args) == 2 {
		annotation := ins.Args[0]
		if target.Kind != OpMem || annotation.Kind != OpReg || !isARMGeneralReg(annotation.Reg) {
			return bad()
		}
	}
	// Preserve the register operand accepted by existing parsed IR callers.
	if target.Kind == OpReg && isARMGeneralReg(target.Reg) && target.Reg != PC && target.Reg != "R15" {
		return target.Reg, true, nil
	}
	if target.Kind != OpMem {
		return "", false, nil
	}
	mem := target.Mem
	if !isARMGeneralReg(mem.Base) || mem.Base == PC || mem.Base == "R15" ||
		mem.Off != 0 || mem.OffRaw != "" || mem.Sym != "" || mem.Segment != "" ||
		mem.Index != "" && !isARMGeneralReg(mem.Index) {
		return bad()
	}
	// Go optab 7 emits just BLX Rn. Its optional first register and any
	// index on the zero-displacement target do not take part in the call.
	return mem.Base, true, nil
}

func armBranchExchangeTarget(ins Instr) (Reg, error) {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return "", err
	}
	bad := func() (Reg, error) {
		return "", fmt.Errorf("arm BX expects a zero-displacement register target: %q", ins.Raw)
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpMem {
		return bad()
	}
	mem := ins.Args[0].Mem
	if !isARMGeneralReg(mem.Base) || mem.Off != 0 || mem.OffRaw != "" || mem.Sym != "" || mem.Segment != "" ||
		mem.Index != "" && !isARMGeneralReg(mem.Index) {
		return bad()
	}
	switch mem.Base {
	case "R13", SP, "R15", PC:
		return "", fmt.Errorf("%w: ARM BX target %s requires original stack or code layout: %q", ErrProbeNeedsContext, mem.Base, ins.Raw)
	}
	// Go's optab 75 uses To.Reg. An index annotation does not contribute
	// to the selected code address.
	return mem.Base, nil
}

const armIndirectCallVFPClobbers = "~{d0},~{d1},~{d2},~{d3},~{d4},~{d5},~{d6},~{d7}," +
	"~{d16},~{d17},~{d18},~{d19},~{d20},~{d21},~{d22},~{d23}," +
	"~{d24},~{d25},~{d26},~{d27},~{d28},~{d29},~{d30},~{d31},~{cc},~{memory}"

var armBranchExchangeRegisters = [...]Reg{"R0", "R1", "R2", "R3", "R12", "R11"}

func (c *armCtx) emitBranchExchange(register Reg) error {
	address, err := c.loadReg(register)
	if err != nil {
		return err
	}
	var operands [6]string
	for i, reg := range armBranchExchangeRegisters[:5] {
		value, err := c.loadReg(reg)
		if err != nil {
			return err
		}
		operands[i] = "i32 " + value
	}
	// Go copies the target to R11 before writing LR. R11 can be LLVM's
	// reserved frame pointer, so preserve it inside the assembly region.
	// The two saved words keep AAPCS alignment at the nested call.
	operands[5] = "i32 " + address
	const carrier = "{i32,i32,i32,i32,i32,i32,i32}"
	const constraints = "={r0},={r1},={r2},={r3},={r12},=&r,=&r,0,1,2,3,4,r,~{lr}," + armIndirectCallVFPClobbers
	const code = "push {r11, lr}; mov r11, $12; blx r11; mov $5, r11; pop {r11, lr}; mrs $6, apsr"
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n",
		result, carrier, code, constraints, strings.Join(operands[:], ", "))
	for i, reg := range armBranchExchangeRegisters {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, carrier, result, i)
		if err := c.storeReg(reg, "%"+value); err != nil {
			return err
		}
	}
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 6\n", status, carrier, result)
	c.storeFlagsFromStatus("%" + status)
	return nil
}

func (c *armCtx) emitIndirectCall(register Reg) error {
	address, err := c.loadReg(register)
	if err != nil {
		return err
	}
	// Physical AAPCS volatile registers may be live in LLVM across this
	// inline-assembly call. Read APSR before any generated code can change it.
	const clobbers = "~{r0},~{r1},~{r2},~{r3},~{r12},~{lr}," + armIndirectCallVFPClobbers
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q(i32 %s)\n",
		status, "blx $1; mrs $0, apsr", "=r,r,"+clobbers, address)
	c.storeFlagsFromStatus("%" + status)
	return nil
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
		// Cross-package trampoline (e.g. sync/atomic -> internal/runtime/atomic).
		// If we don't have an explicit signature, fall back to caller signature.
		csig = c.sig
		csig.Name = callee
	}
	if csig.ARMEntry != nil {
		return fmt.Errorf("%w: ARM machine entry %q has no ordinary typed tail-call ABI", ErrProbeNeedsContext, callee)
	}
	callee = funcSigSymbol(callee, csig)
	args := make([]string, 0, len(csig.Args))
	useLLVMArgs := len(csig.ArgRegs) == 0 && len(csig.Args) == len(c.sig.Args) && csig.Ret == c.sig.Ret
	if useLLVMArgs {
		for i := range csig.Args {
			if csig.Args[i] != c.sig.Args[i] {
				useLLVMArgs = false
				break
			}
		}
	}
	for i := 0; i < len(csig.Args); i++ {
		if useLLVMArgs {
			args = append(args, fmt.Sprintf("%s %%arg%d", csig.Args[i], i))
			continue
		}
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
	if c.sig.Ret == Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	if c.sig.Ret != csig.Ret {
		conv := c.newTmp()
		calleeBits, calleeInteger := armIntegerTypeWidth(csig.Ret)
		callerBits, callerInteger := armIntegerTypeWidth(c.sig.Ret)
		switch {
		case calleeInteger && callerInteger && calleeBits > callerBits:
			fmt.Fprintf(c.b, "  %%%s = trunc %s %%%s to %s\n", conv, csig.Ret, t, c.sig.Ret)
		case calleeInteger && callerInteger && calleeBits < callerBits:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to %s\n", conv, csig.Ret, t, c.sig.Ret)
		case csig.Ret == I32 && (c.sig.Ret == I1 || c.sig.Ret == I8 || c.sig.Ret == I16):
			fmt.Fprintf(c.b, "  %%%s = trunc i32 %%%s to %s\n", conv, t, c.sig.Ret)
		case (csig.Ret == I1 || csig.Ret == I8 || csig.Ret == I16) && c.sig.Ret == I32:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i32\n", conv, csig.Ret, t)
		case csig.Ret == Ptr && c.sig.Ret == I32:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i32\n", conv, t)
		case csig.Ret == I32 && c.sig.Ret == Ptr:
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

func armIntegerTypeWidth(typ LLVMType) (int, bool) {
	switch typ {
	case I1:
		return 1, true
	case I8:
		return 8, true
	case I16:
		return 16, true
	case I32:
		return 32, true
	case I64:
		return 64, true
	default:
		return 0, false
	}
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
	if csig.ARMEntry != nil {
		return fmt.Errorf("%w: ARM machine entry %q requires a physical call-site bridge", ErrProbeNeedsContext, callee)
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
		c.captureHardwareFlags()
		return nil
	}
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	c.captureHardwareFlags()
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
