package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerBranch(bi int, ii int, op Op, ins Instr, emitBr amd64EmitBr, emitCondBr amd64EmitCondBr) (ok bool, terminated bool, err error) {
	switch op {
	case "CALL":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 CALL expects 1 operand: %q", ins.Raw)
		}
		switch ins.Args[0].Kind {
		case OpReg:
			addr, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			if err := c.callIndirectAddr(addr); err != nil {
				return true, false, err
			}
			return true, false, nil
		case OpMem:
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
		case OpSym:
			if strings.HasPrefix(strings.TrimSpace(ins.Args[0].Sym), "*") {
				addr, err := c.loadIndirectSymbolAddr(ins.Args[0].Sym)
				if err != nil {
					return true, false, err
				}
				if err := c.callIndirectAddr(addr); err != nil {
					return true, false, err
				}
				return true, false, nil
			}
			if err := c.callSym(ins.Args[0]); err != nil {
				return true, false, err
			}
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 CALL expects reg or symbol(SB) target: %q", ins.Raw)
		}

	default:
		if op != "JMP" && op != "LOOP" && !isAMD64ConditionalBranch(op) {
			return false, false, nil
		}
	}
	args := ins.Args
	// The Go assembler accepts a legacy x86 branch-hint operand such as
	// JEQ $1, target. It is not part of the encoded instruction on current
	// toolchains, so preserve control flow and ignore the hint value.
	if op != "JMP" && op != "LOOP" && !isAMD64CounterZeroBranch(op) && len(args) == 2 && args[0].Kind == OpImm {
		if args[0].Imm != 0 && args[0].Imm != 1 {
			return true, false, fmt.Errorf("amd64 %s branch hint must be $0 or $1: %q", op, ins.Raw)
		}
		args = args[1:]
	}
	if len(args) != 1 {
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
	switch args[0].Kind {
	case OpIdent:
		target = args[0].Ident
	case OpReg:
		// Labels like V1 may be tokenized as registers. Prefer block labels;
		// otherwise treat JMP reg as an indirect tail jump.
		name := string(args[0].Reg)
		if knownBlock(name) {
			target = name
			break
		}
		if op == "JMP" {
			addr, err := c.loadReg(args[0].Reg)
			if err != nil {
				return true, false, err
			}
			if err := c.tailCallIndirectAddrAndRet(addr); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		return true, false, fmt.Errorf("amd64 %s invalid register target: %q", op, ins.Raw)
	case OpSym:
		s := strings.TrimSpace(args[0].Sym)
		if op == "JMP" && strings.HasPrefix(s, "*") {
			addr, err := c.loadIndirectSymbolAddr(s)
			if err != nil {
				return true, false, err
			}
			if err := c.tailCallIndirectAddrAndRet(addr); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		// Treat JMP foo(SB) as a tailcall to another TEXT (common in stdlib asm).
		if op == "JMP" && strings.HasSuffix(s, "(SB)") {
			if err := c.tailCallAndRet(args[0]); err != nil {
				return true, false, err
			}
			return true, true, nil
		}
		// Local labels sometimes appear with "<>" or (SB) suffix.
		s = strings.TrimSuffix(strings.TrimSuffix(s, "(SB)"), "<>")
		target = s
	case OpMem:
		// PC-relative branches like "JEQ 2(PC)" are used as a compact way to skip
		// the next instruction. Handle them by mapping the offset to our block
		// sequence (blocks are split at terminators, so the pattern works well).
		if strings.EqualFold(string(args[0].Mem.Base), "PC") {
			pcRel = true
			pcOff = args[0].Mem.Off
			break
		}
		if op == "JMP" {
			addr, err := c.addrFromMem(args[0].Mem)
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
	case "LOOP":
		counter, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		if c.goarch == "386" {
			old32 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", old32, counter)
			next32 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", next32, old32)
			next64 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", next64, next32)
			if err := c.storeReg(CX, "%"+next64); err != nil {
				return true, false, err
			}
			test := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", test, next32)
			cond = "%" + test
		} else {
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 1\n", next, counter)
			if err := c.storeReg(CX, "%"+next); err != nil {
				return true, false, err
			}
			test := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", test, next)
			cond = "%" + test
		}
	case "JCXZW", "JCXZL", "JCXZQ":
		// cmd/internal/obj/x86 emits an address-size override only for
		// JCXZL. Therefore Go's historical spellings test these widths:
		//
		//             JCXZW  JCXZL  JCXZQ
		//   amd64       RCX    ECX    RCX
		//   386         ECX     CX    ECX
		//
		// Preserve that behavior instead of inferring the width from the
		// mnemonic suffix.
		counter, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		bits := 64
		if c.goarch == "386" {
			bits = 32
		}
		if op == "JCXZL" {
			bits /= 2
		}
		value := counter
		if bits != 64 {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, counter, bits)
			value = "%" + truncated
		}
		test := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %s, 0\n", test, bits, value)
		cond = "%" + test
	case "JE", "JEQ", "JZ":
		cond, err = c.x86Condition("EQ")
	case "JNE", "JNZ":
		cond, err = c.x86Condition("NE")
	case "JL", "JLT", "JNGE":
		cond, err = c.x86Condition("LT")
	case "JGE", "JNL":
		cond, err = c.x86Condition("GE")
	case "JS", "JMI":
		cond, err = c.x86Condition("MI")
	case "JNS", "JPL":
		cond, err = c.x86Condition("PL")
	case "JLE", "JNG":
		cond, err = c.x86Condition("LE")
	case "JG", "JGT", "JNLE":
		cond, err = c.x86Condition("GT")
	case "JB", "JLO", "JC", "JCS", "JNAE":
		cond, err = c.x86Condition("CS")
	case "JNC", "JCC", "JAE", "JHS", "JNB":
		cond, err = c.x86Condition("CC")
	case "JBE", "JLS", "JNA":
		cond, err = c.x86Condition("LS")
	case "JA", "JHI", "JNBE":
		cond, err = c.x86Condition("HI")
	case "JO", "JOS":
		cond, err = c.x86Condition("OS")
	case "JNO", "JOC":
		cond, err = c.x86Condition("OC")
	case "JP", "JPE", "JPS":
		cond, err = c.x86Condition("PS")
	case "JNP", "JPO", "JPC":
		cond, err = c.x86Condition("PC")
	default:
		return true, false, fmt.Errorf("amd64: unsupported branch %s", op)
	}
	if err != nil {
		return true, false, err
	}

	if err := emitCondBr(cond, target, fall); err != nil {
		return true, false, err
	}
	return true, true, nil
}

func (c *amd64Ctx) loadIndirectSymbolAddr(sym string) (string, error) {
	sym = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sym), "*"))
	if !strings.HasSuffix(sym, "(SB)") {
		return "", fmt.Errorf("amd64 indirect branch expects register, memory, or *symbol(SB), got %q", sym)
	}
	ptr, err := c.ptrFromSB(sym)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	if c.goarch == "386" {
		fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", value, ptr)
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, value)
		return "%" + wide, nil
	}
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", value, ptr)
	return "%" + value, nil
}

func (c *amd64Ctx) callIndirectAddr(addr string) error {
	fptr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", fptr, addr)
	di, _ := c.loadReg(DI)
	si, _ := c.loadReg(SI)
	dx, _ := c.loadReg(DX)
	cx, _ := c.loadReg(CX)
	r8, _ := c.loadReg(Reg("R8"))
	r9, _ := c.loadReg(Reg("R9"))
	ret := c.newTmp()
	// Model as a generic C-ABI style call carrying register arguments.
	fmt.Fprintf(c.b, "  %%%s = call i64 %%%s(i64 %s, i64 %s, i64 %s, i64 %s, i64 %s, i64 %s)\n", ret, fptr, di, si, dx, cx, r8, r9)
	return c.storeReg(AX, "%"+ret)
}

func (c *amd64Ctx) tailCallIndirectAddrAndRet(addr string) error {
	if len(c.indirectLabels) != 0 {
		ptr := c.ptrFromAddrI64(addr)
		labels := make([]string, len(c.indirectLabels))
		for i, label := range c.indirectLabels {
			labels[i] = "label %" + amd64LLVMBlockName(label)
		}
		fmt.Fprintf(c.b, "  indirectbr ptr %s, [%s]\n", ptr, strings.Join(labels, ", "))
		return nil
	}
	if err := c.callIndirectAddr(addr); err != nil {
		return err
	}
	return c.lowerRET()
}

func (c *amd64Ctx) castI64RegToArg(v string, to LLVMType) (string, error) {
	switch to {
	case I64:
		return v, nil
	case I1, I8, I16, I32:
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

func (c *amd64Ctx) structArgFromSequentialRegs(aggTy LLVMType, regs []Reg, regCursor *int) (string, error) {
	fields, ok := parseLiteralStructFields(aggTy)
	if !ok || !literalFieldsAllScalar(fields) {
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

func (c *amd64Ctx) callSym(symOp Operand) error {
	if symOp.Kind != OpSym {
		return fmt.Errorf("amd64 call expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("amd64 call expects (SB) symbol, got %q", s)
	}
	internalABI := strings.HasSuffix(strings.TrimSuffix(s, "(SB)"), "<ABIInternal>")
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
	callee = funcSigSymbol(callee, csig)

	stackABI := !internalABI && len(csig.ArgRegs) == 0 && len(csig.Frame.Params) != 0
	if stackABI {
		args, err := c.abi0CallArgs(callee, csig)
		if err != nil {
			return err
		}
		if csig.Ret == Void {
			fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
			return nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
		if len(csig.Frame.Results) != 0 {
			return c.storeABI0CallResult(callee, csig, "%"+t)
		}
		return fmt.Errorf("amd64 call %q: ABI0 result %s has no frame slot", callee, csig.Ret)
	}

	args := make([]string, 0, len(csig.Args))
	goABI := []Reg{AX, BX, CX, DI, SI, Reg("R8"), Reg("R9"), Reg("R10"), Reg("R11")}
	regCursor := 0
	for i, argTy := range csig.Args {
		if len(csig.ArgRegs) == 0 {
			if fields, ok := parseLiteralStructFields(argTy); ok && literalFieldsAllScalar(fields) {
				agg, err := c.structArgFromSequentialRegs(argTy, goABI, &regCursor)
				if err != nil {
					return fmt.Errorf("amd64 call %q: %w", callee, err)
				}
				args = append(args, fmt.Sprintf("%s %s", argTy, agg))
				continue
			}
		}

		var r Reg
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

	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		return nil
	}

	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	switch csig.Ret {
	case I64:
		return c.storeReg(AX, "%"+t)
	case I1, I8, I16, I32:
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", z, csig.Ret, t)
		return c.storeReg(AX, "%"+z)
	case Ptr:
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", p, t)
		return c.storeReg(AX, "%"+p)
	default:
		fields, ok := parseLiteralStructFields(csig.Ret)
		if !ok || !literalFieldsAllScalar(fields) {
			return fmt.Errorf("amd64 call %q unsupported return type %s", callee, csig.Ret)
		}
		resultRegs := []Reg{AX, BX, CX, DI, SI, Reg("R8"), Reg("R9"), Reg("R10"), Reg("R11")}
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

func (c *amd64Ctx) tailCallAndRet(symOp Operand) error {
	if symOp.Kind != OpSym {
		return fmt.Errorf("amd64 tailcall expects sym operand, got %s", symOp.String())
	}
	s := strings.TrimSpace(symOp.Sym)
	if !strings.HasSuffix(s, "(SB)") {
		return fmt.Errorf("amd64 tailcall expects (SB) symbol, got %q", s)
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
	callee = funcSigSymbol(callee, csig)

	args := make([]string, 0, len(csig.Args))
	for i := 0; i < len(csig.Args); i++ {
		// If ArgRegs is empty, default to register-based passing (ABIInternal-ish)
		// because most intra-asm tailcalls depend on explicit register setup.
		//
		// Exception: for tailcalls to Go functions with identical argument types,
		// use the current function's LLVM args. This matches stdlib patterns like
		// "JMP ·countGeneric(SB)" that happen before any register shuffling and
		// are stack-ABI tailcalls in the original asm. The return types may differ
		// while using ABI-equivalent physical result slots.
		useLLVMArgs := false
		if len(csig.ArgRegs) == 0 && len(csig.Args) == len(c.sig.Args) {
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
			case fromTy == I64 && (toTy == I1 || toTy == I8 || toTy == I16 || toTy == I32):
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, fromVal, toTy)
				args = append(args, fmt.Sprintf("%s %%%s", toTy, t))
			case (fromTy == I1 || fromTy == I8 || fromTy == I16 || fromTy == I32) && toTy == I64:
				fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", t, fromTy, fromVal)
				args = append(args, fmt.Sprintf("i64 %%%s", t))
			case fromTy == I64 && toTy == Ptr:
				fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, fromVal)
				args = append(args, fmt.Sprintf("ptr %%%s", t))
			case fromTy == Ptr && toTy == I64:
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, fromVal)
				args = append(args, fmt.Sprintf("i64 %%%s", t))
			default:
				return fmt.Errorf("amd64 tailcall %q: unsupported arg cast %s -> %s", callee, fromTy, toTy)
			}
			continue
		}

		r := Reg("")
		if i < len(csig.ArgRegs) {
			r = csig.ArgRegs[i]
		} else {
			// Default SysV-ish register order: DI, SI, DX, CX, R8, R9.
			x86 := []Reg{DI, SI, DX, CX, Reg("R8"), Reg("R9")}
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
		case I64:
			args = append(args, "i64 "+v)
		case I1:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", t, v)
			args = append(args, "i1 %"+t)
		case I8:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, v)
			args = append(args, "i8 %"+t)
		case I16:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, v)
			args = append(args, "i16 %"+t)
		case I32:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, v)
			args = append(args, "i32 %"+t)
		case Ptr:
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", t, v)
			args = append(args, "ptr %"+t)
		default:
			return fmt.Errorf("amd64 tailcall unsupported arg type %q", csig.Args[i])
		}
	}

	if csig.Ret == Void {
		fmt.Fprintf(c.b, "  call void %s(%s)\n", llvmGlobal(callee), strings.Join(args, ", "))
		// If caller returns via classic FP result slots, return from those after the call.
		if len(c.fpResults) > 0 {
			return c.lowerRET()
		}
		if c.sig.Ret == Void {
			c.b.WriteString("  ret void\n")
			return nil
		}
		return fmt.Errorf("amd64 tailcall to %q returns void but caller expects %s", callee, c.sig.Ret)
	}

	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s %s(%s)\n", t, csig.Ret, llvmGlobal(callee), strings.Join(args, ", "))
	if c.sig.Ret == Void {
		c.b.WriteString("  ret void\n")
		return nil
	}
	if c.sig.Ret != csig.Ret {
		if adapted, ok, err := c.adaptTailCallAggregateReturn("%"+t, csig.Ret, c.sig.Ret); err != nil {
			return fmt.Errorf("amd64 tailcall return type mismatch for %q: %w", callee, err)
		} else if ok {
			fmt.Fprintf(c.b, "  ret %s %s\n", c.sig.Ret, adapted)
			return nil
		}
		conv := c.newTmp()
		switch {
		case c.goarch == "386" && csig.Ret == I32 && c.sig.Ret == Ptr:
			fmt.Fprintf(c.b, "  %%%s = inttoptr i32 %%%s to ptr\n", conv, t)
			fmt.Fprintf(c.b, "  ret ptr %%%s\n", conv)
			return nil
		case c.goarch == "386" && csig.Ret == Ptr && c.sig.Ret == I32:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i32\n", conv, t)
			fmt.Fprintf(c.b, "  ret i32 %%%s\n", conv)
			return nil
		case csig.Ret == I64 && (c.sig.Ret == I1 || c.sig.Ret == I8 || c.sig.Ret == I16 || c.sig.Ret == I32):
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", conv, t, c.sig.Ret)
			fmt.Fprintf(c.b, "  ret %s %%%s\n", c.sig.Ret, conv)
			return nil
		case (csig.Ret == I1 || csig.Ret == I8 || csig.Ret == I16 || csig.Ret == I32) && c.sig.Ret == I64:
			fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", conv, csig.Ret, t)
			fmt.Fprintf(c.b, "  ret i64 %%%s\n", conv)
			return nil
		case csig.Ret == Ptr && c.sig.Ret == I64:
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %%%s to i64\n", conv, t)
			fmt.Fprintf(c.b, "  ret i64 %%%s\n", conv)
			return nil
		case csig.Ret == I64 && c.sig.Ret == Ptr:
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

func (c *amd64Ctx) adaptTailCallAggregateReturn(value string, fromTy, toTy LLVMType) (string, bool, error) {
	fromFields, fromAggregate := parseLiteralStructFields(fromTy)
	toFields, toAggregate := parseLiteralStructFields(toTy)
	if !fromAggregate || !toAggregate {
		return "", false, nil
	}
	if len(fromFields) != len(toFields) {
		return "", false, fmt.Errorf("caller %s and callee %s use different aggregate field counts", toTy, fromTy)
	}

	wordTy := I64
	if c.goarch == "386" {
		wordTy = I32
	}
	for i := range fromFields {
		from, to := fromFields[i], toFields[i]
		if from == to || (from == wordTy && to == Ptr) || (from == Ptr && to == wordTy) {
			continue
		}
		return "", false, fmt.Errorf("caller field %d has type %s but callee field has ABI-incompatible type %s", i, to, from)
	}

	result := "undef"
	for i := range fromFields {
		from, to := fromFields[i], toFields[i]
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, %d\n", extracted, fromTy, value, i)
		field := "%" + extracted
		if from != to {
			converted := c.newTmp()
			if from == wordTy && to == Ptr {
				fmt.Fprintf(c.b, "  %%%s = inttoptr %s %s to ptr\n", converted, wordTy, field)
			} else {
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to %s\n", converted, field, wordTy)
			}
			field = "%" + converted
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertvalue %s %s, %s %s, %d\n", inserted, toTy, result, to, field, i)
		result = "%" + inserted
	}
	return result, true, nil
}
