package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) loadIntDestination(dst Operand, ty LLVMType) (string, func(string) error, error) {
	switch dst.Kind {
	case OpReg:
		v, err := c.evalIntSized(dst, ty)
		if err != nil {
			return "", nil, err
		}
		return v, func(out string) error { return c.storeRegSized(dst.Reg, ty, out) }, nil
	case OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return "", nil, err
		}
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", v, ty, ptrType, p)
		return "%" + v, func(out string) error {
			fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", ty, out, ptrType, p)
			return nil
		}, nil
	case OpFP:
		value, err := c.evalFPToI64(dst.FPOffset)
		if err != nil {
			return "", nil, err
		}
		if ty != I64 {
			value = c.truncI64(value, ty)
		}
		return value, func(out string) error {
			return c.storeFPResult(dst.FPOffset, ty, out)
		}, nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return "", nil, err
		}
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", v, ty, p)
		return "%" + v, func(out string) error {
			fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", ty, out, p)
			return nil
		}, nil
	default:
		return "", nil, fmt.Errorf("expected register or memory destination, got %s", dst.String())
	}
}

type x86FlagSlot struct {
	slot string
	bit  uint
}

func (c *amd64Ctx) x86FlagSlots() []x86FlagSlot {
	flags := []x86FlagSlot{
		{c.flagsCFSlot, 0},
		{c.flagsPFSlot, 2},
		{c.flagsZSlot, 6},
		{c.flagsSltSlot, 7},
	}
	if c.directionSlot != "" {
		flags = append(flags, x86FlagSlot{c.directionSlot, 10})
	}
	flags = append(flags, x86FlagSlot{c.flagsOFSlot, 11})
	if c.flagsIDSlot != "" {
		flags = append(flags, x86FlagSlot{c.flagsIDSlot, 21})
	}
	return flags
}

func (c *amd64Ctx) packX86Flags() string {
	packed := "2" // architectural bit 1 is always set
	for _, flag := range c.x86FlagSlots() {
		v := c.loadFlag(flag.slot)
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", ext, v)
		part := "%" + ext
		if flag.bit != 0 {
			shift := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", shift, ext, flag.bit)
			part = "%" + shift
		}
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %s, %s\n", next, packed, part)
		packed = "%" + next
	}
	return packed
}

func (c *amd64Ctx) unpackX86Flags(packed string) {
	for _, flag := range c.x86FlagSlots() {
		shifted := packed
		if flag.bit != 0 {
			shift := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shift, packed, flag.bit)
			shifted = "%" + shift
		}
		bit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i1\n", bit, shifted)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", bit, flag.slot)
	}
}

func (c *amd64Ctx) truncI64(v string, ty LLVMType) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v, ty)
	return "%" + t
}

func isGoYmbRegisterForArch(r Reg, goarch string) bool {
	if goarch == "386" {
		// Go classifies SP/BP/SI/DI as Yrl32 in 386 mode, so they do not
		// directly cover Ymb. Its assembler nevertheless accepts BP/SI/DI
		// and synthesizes an equivalent sequence through BX; only a direct
		// SP spelling remains invalid.
		switch r {
		case AX, BX, CX, DX, BP, SI, DI, AL, AH, BL, BH, CL, CH, DL, DH:
			return true
		default:
			return false
		}
	}
	if isX86YrlRegisterForArch(r, goarch) {
		return true
	}
	switch r {
	case AL, AH, BL, BH, CL, CH, DL, DH,
		BPB, SIB, DIB, R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B:
		return true
	default:
		return false
	}
}

// amd64YmbEffectiveRegister mirrors the raw ModRM numbering used when Go's
// broad Ymb table accepts a byte-register spelling for a wider NEG/NOT opcode.
func amd64YmbEffectiveRegister(r Reg, bits int) Reg {
	if bits == 8 {
		return r
	}
	switch r {
	case AL:
		return AX
	case CL:
		return CX
	case DL:
		return DX
	case BL:
		return BX
	case AH:
		return SP
	case CH:
		return BP
	case DH:
		return SI
	case BH:
		return DI
	default:
		if base, _, ok := amd64ByteAlias(r); ok {
			return base
		}
		return r
	}
}

func (c *amd64Ctx) lowerArith(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerStackWidth(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerAccumulatorSignExtend(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerBZHI(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerBEXTR(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerADX(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerLeadingZeroCount(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerBMI2VariableShift(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerScalarUnaryYmb(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerLowestSetBitManipulation(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerHardwareRandom(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerScalarADCSBB(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerScalarMultiplyDivide(op, ins); ok {
		return ok, terminated, err
	}
	switch op {
	case "PUSHAL":
		if c.goarch != "386" {
			return true, false, fmt.Errorf("amd64 PUSHAL requires GOARCH=386")
		}
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("amd64 PUSHAL takes no operands: %q", ins.Raw)
		}
		originalSP, err := c.loadReg(SP)
		if err != nil {
			return true, false, err
		}
		pushReg := func(r Reg) error {
			v, err := c.loadReg(r)
			if err != nil {
				return err
			}
			return c.pushI32(c.truncI64(v, I32))
		}
		for _, r := range []Reg{AX, CX, DX, BX} {
			if err := pushReg(r); err != nil {
				return true, false, err
			}
		}
		if err := c.pushI32(c.truncI64(originalSP, I32)); err != nil {
			return true, false, err
		}
		for _, r := range []Reg{BP, SI, DI} {
			if err := pushReg(r); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	case "POPAL":
		if c.goarch != "386" {
			return true, false, fmt.Errorf("amd64 POPAL requires GOARCH=386")
		}
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("amd64 POPAL takes no operands: %q", ins.Raw)
		}
		for _, r := range []Reg{DI, SI, BP} {
			v, err := c.popI32()
			if err != nil {
				return true, false, err
			}
			if err := c.storeRegSized(r, I32, v); err != nil {
				return true, false, err
			}
		}
		if _, err := c.popI32(); err != nil { // POPAL deliberately does not restore SP.
			return true, false, err
		}
		for _, r := range []Reg{BX, DX, CX, AX} {
			v, err := c.popI32()
			if err != nil {
				return true, false, err
			}
			if err := c.storeRegSized(r, I32, v); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	case "LFENCE", "MFENCE", "SFENCE", "PAUSE":
		if c.goarch == "386" {
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", strings.ToLower(string(op)), "~{memory}")
		}
		return true, false, nil
	case "PREFETCHNTA", "PREFETCHT0", "PREFETCHT1", "PREFETCHT2",
		"PREFETCHRST2", "PREFETCHIT0", "PREFETCHIT1":
		// Go 1.27's shared yprefetch table has exactly one memory operand for
		// each named locality hint. The raw-only 0F 18 /4, /6 and /7 forms
		// share that one-memory-operand grammar. Cache hints have no
		// SSA-visible result.
		if len(ins.Args) != 1 || !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s expects one memory operand: %q", c.goarch, op, ins.Raw)
		}
		return true, false, nil
	case "EMMS":
		// MMX registers are modeled as ordinary integers, so there is no
		// hardware x87 tag state to clear.
		return true, false, nil
	case "UNDEF":
		if c.goarch == "386" {
			c.emitX86Trap()
			return true, true, nil
		}
		// Preserve the historical amd64 approximation.
		return true, false, nil
	case "RDTSC":
		if c.goarch == "386" {
			if len(ins.Args) != 0 {
				return true, false, fmt.Errorf("386 RDTSC takes no operands: %q", ins.Raw)
			}
			return true, false, c.lower386Timestamp(false)
		}
		if err := c.storeReg(AX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "RDPID":
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 1 || ins.Args[0].Kind != OpReg || !isAMD64YrlRegister(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("%s RDPID expects one general register with no suffix: %q", c.goarch, ins.Raw)
		}
		if c.goarch == "386" && amd64IsExtendedGPRegister(ins.Args[0].Reg) {
			return true, false, fmt.Errorf("386 RDPID destination is outside the 386 register file: %q", ins.Raw)
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.rdpid()\n", value)
		return true, false, c.storeRegSized(ins.Args[0].Reg, I32, "%"+value)
	case OpCPUID:
		eax64, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		ecx64, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		eax32 := c.newTmp()
		ecx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", eax32, eax64)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ecx32, ecx64)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32, i32, i32 } asm sideeffect \"cpuid\", \"={ax},={bx},={cx},={dx},{ax},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %%%s, i32 %%%s)\n", call, eax32, ecx32)
		storeOut := func(idx int, reg Reg) error {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32, i32, i32 } %%%s, %d\n", part, call, idx)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, part)
			return c.storeReg(reg, "%"+wide)
		}
		if err := storeOut(0, AX); err != nil {
			return true, false, err
		}
		if err := storeOut(1, BX); err != nil {
			return true, false, err
		}
		if err := storeOut(2, CX); err != nil {
			return true, false, err
		}
		if err := storeOut(3, DX); err != nil {
			return true, false, err
		}
		return true, false, nil
	case OpXGETBV:
		ecx64, err := c.loadReg(CX)
		if err != nil {
			return true, false, err
		}
		ecx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", ecx32, ecx64)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect \"xgetbv\", \"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %%%s)\n", call, ecx32)
		storeOut := func(idx int, reg Reg) error {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, idx)
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", wide, part)
			return c.storeReg(reg, "%"+wide)
		}
		if err := storeOut(0, AX); err != nil {
			return true, false, err
		}
		if err := storeOut(1, DX); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "RDTSCP":
		if c.goarch == "386" {
			if len(ins.Args) != 0 {
				return true, false, fmt.Errorf("386 RDTSCP takes no operands: %q", ins.Raw)
			}
			return true, false, c.lower386Timestamp(true)
		}
		if err := c.storeReg(AX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DX, "0"); err != nil {
			return true, false, err
		}
		if err := c.storeReg(CX, "0"); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "MOVSB":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ps := c.ptrFromAddrI64(si)
		pd := c.ptrFromAddrI64(di)
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s, align 1\n", v, ps)
		fmt.Fprintf(c.b, "  store i8 %%%s, ptr %s, align 1\n", v, pd)
		ns := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", ns, si)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", nd, di)
		if err := c.storeReg(SI, "%"+ns); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "MOVSQ":
		si, err := c.loadReg(SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ps := c.ptrFromAddrI64(si)
		pd := c.ptrFromAddrI64(di)
		v := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", v, ps)
		fmt.Fprintf(c.b, "  store i64 %%%s, ptr %s, align 1\n", v, pd)
		ns := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", ns, si)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", nd, di)
		if err := c.storeReg(SI, "%"+ns); err != nil {
			return true, false, err
		}
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "STOSQ":
		di, err := c.loadReg(DI)
		if err != nil {
			return true, false, err
		}
		ax, err := c.loadReg(AX)
		if err != nil {
			return true, false, err
		}
		pd := c.ptrFromAddrI64(di)
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", ax, pd)
		nd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, 8\n", nd, di)
		if err := c.storeReg(DI, "%"+nd); err != nil {
			return true, false, err
		}
		return true, false, nil
	case "ADDQ", "SUBQ", "XORQ", "ANDQ", "ORQ":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		loadDst := func() (string, func(string) error, error) {
			switch ins.Args[1].Kind {
			case OpReg:
				dst := ins.Args[1].Reg
				dv, err := c.loadReg(dst)
				if err != nil {
					return "", nil, err
				}
				return dv, func(v string) error { return c.storeReg(dst, v) }, nil
			case OpMem:
				addr, err := c.addrFromMem(ins.Args[1].Mem)
				if err != nil {
					return "", nil, err
				}
				p := c.ptrFromAddrI64(addr)
				ld := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
				return "%" + ld, func(v string) error {
					fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", v, p)
					return nil
				}, nil
			default:
				return "", nil, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
			}
		}
		dv, storeDst, err := loadDst()
		if err != nil {
			return true, false, err
		}
		t := c.newTmp()
		switch op {
		case "ADDQ":
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", t, dv, src)
		case "SUBQ":
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", t, dv, src)
		case "XORQ":
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", t, dv, src)
		case "ANDQ":
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", t, dv, src)
		case "ORQ":
			fmt.Fprintf(c.b, "  %%%s = or i64 %s, %s\n", t, dv, src)
		}
		r := "%" + t
		if err := storeDst(r); err != nil {
			return true, false, err
		}
		switch op {
		case "ADDQ":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", cf, r, dv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUBQ":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %s\n", cf, dv, src)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		if op == "ADDQ" || op == "SUBQ" {
			xorOperands := c.newTmp()
			xorResult := c.newTmp()
			overflowBits := c.newTmp()
			overflow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", xorOperands, dv, src)
			if op == "ADDQ" {
				inverted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = xor i64 %%%s, -1\n", inverted, xorOperands)
				xorOperands = inverted
			}
			fmt.Fprintf(c.b, "  %%%s = xor i64 %s, %s\n", xorResult, dv, r)
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %%%s\n", overflowBits, xorOperands, xorResult)
			fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, 0\n", overflow, overflowBits)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", overflow, c.flagsOFSlot)
		} else {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		}
		c.setZSFlagsFromI64(r)
		return true, false, nil

	case "ADCL", "SBBL":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], I32)
		if err != nil {
			return true, false, err
		}
		dst, storeDst, err := c.loadIntDestination(ins.Args[1], I32)
		if err != nil {
			return true, false, err
		}
		carry := c.loadFlag(c.flagsCFSlot)
		carry64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", carry64, carry)
		src64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", src64, src)
		dst64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", dst64, dst)
		result64 := c.newTmp()
		if op == "ADCL" {
			partial := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", partial, dst64, src64)
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", result64, partial, carry64)
		} else {
			partial := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", partial, src64, carry64)
			fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %%%s\n", result64, dst64, partial)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", result, result64)
		if err := storeDst("%" + result); err != nil {
			return true, false, err
		}
		newCarry := c.newTmp()
		if op == "ADCL" {
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i64 %%%s, 4294967295\n", newCarry, result64)
		} else {
			subtrahend := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", subtrahend, src64, carry64)
			fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %%%s, %%%s\n", newCarry, dst64, subtrahend)
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", newCarry, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI32("%" + result)
		return true, false, nil

	case "ADCQ", "SBBQ":
		// Add/subtract with carry/borrow: src, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		cfIn := c.loadFlag(c.flagsCFSlot)
		cf64t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", cf64t, cfIn)
		cf64 := "%" + cf64t

		dv128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", dv128, dv)
		src128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", src128, src)
		cf128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", cf128, cf64)

		if op == "ADCQ" {
			sum := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", sum, dv, src)
			res := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %s\n", res, sum, cf64)
			out := "%" + res
			if err := c.storeReg(dst, out); err != nil {
				return true, false, err
			}

			total1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total1, dv128, src128)
			total2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", total2, total1, cf128)
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i128 %%%s, 18446744073709551615\n", cf, total2)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
			c.setZSFlagsFromI64(out)
			return true, false, nil
		}

		subtr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i128 %%%s, %%%s\n", subtr, src128, cf128)
		borrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i128 %%%s, %%%s\n", borrow, dv128, subtr)
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", res, dv, src)
		res2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %s\n", res2, res, cf64)
		out := "%" + res2
		if err := c.storeReg(dst, out); err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", borrow, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI64(out)
		return true, false, nil

	case "ADCB":
		// 8-bit add with carry: src, dstReg/mem.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		var d8 string
		var storeDst func(string) error
		switch ins.Args[1].Kind {
		case OpReg:
			dst := ins.Args[1].Reg
			dv64, err := c.loadReg(dst)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", t, dv64)
			d8 = "%" + t
			storeDst = func(v8 string) error {
				return c.storeRegSized(dst, I8, v8)
			}
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[1].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i8, ptr %s, align 1\n", ld, p)
			d8 = "%" + ld
			storeDst = func(v8 string) error {
				fmt.Fprintf(c.b, "  store i8 %s, ptr %s, align 1\n", v8, p)
				return nil
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}

		s8, err := c.evalIntSized(ins.Args[0], I8)
		if err != nil {
			return true, false, err
		}
		cfIn := c.loadFlag(c.flagsCFSlot)
		cf8t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i8\n", cf8t, cfIn)
		cf8 := "%" + cf8t

		sum := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i8 %s, %s\n", sum, d8, s8)
		res := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i8 %%%s, %s\n", res, sum, cf8)
		out8 := "%" + res
		if err := storeDst(out8); err != nil {
			return true, false, err
		}

		d16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", d16, d8)
		s16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", s16, s8)
		cf16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", cf16, cf8)
		total1 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total1, d16, s16)
		total2 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total2, total1, cf16)
		cf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ugt i16 %%%s, 255\n", cf, total2)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, res)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", sf, res)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		return true, false, nil

	case "ADDL", "SUBL", "XORL", "ANDL", "ORL":
		// 32-bit arithmetic/logical ops: src, dst.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		s32, err := c.evalIntSized(ins.Args[0], I32)
		if err != nil {
			return true, false, err
		}
		dtr, storeDst, err := c.loadIntDestination(ins.Args[1], I32)
		if err != nil {
			return true, false, err
		}
		x := c.newTmp()
		switch op {
		case "ADDL":
			fmt.Fprintf(c.b, "  %%%s = add i32 %s, %s\n", x, dtr, s32)
		case "SUBL":
			fmt.Fprintf(c.b, "  %%%s = sub i32 %s, %s\n", x, dtr, s32)
		case "XORL":
			fmt.Fprintf(c.b, "  %%%s = xor i32 %s, %s\n", x, dtr, s32)
		case "ANDL":
			fmt.Fprintf(c.b, "  %%%s = and i32 %s, %s\n", x, dtr, s32)
		case "ORL":
			fmt.Fprintf(c.b, "  %%%s = or i32 %s, %s\n", x, dtr, s32)
		}
		if err := storeDst("%" + x); err != nil {
			return true, false, err
		}
		switch op {
		case "ADDL":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %%%s, %s\n", cf, x, dtr)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUBL":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i32 %s, %s\n", cf, dtr, s32)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		c.setZSFlagsFromI32("%" + x)
		return true, false, nil

	case "ADDB", "SUBB", "XORB", "ANDB", "ORB":
		// 8-bit scalar ops: src, dst. Go's x86 assembler permits both a
		// register and a memory destination (for example XORB SI, (AX)).
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		d8, storeDst, err := c.loadIntDestination(ins.Args[1], I8)
		if err != nil {
			return true, false, err
		}
		s8, err := c.evalIntSized(ins.Args[0], I8)
		if err != nil {
			return true, false, err
		}
		x := c.newTmp()
		switch op {
		case "ADDB":
			fmt.Fprintf(c.b, "  %%%s = add i8 %s, %s\n", x, d8, s8)
		case "SUBB":
			fmt.Fprintf(c.b, "  %%%s = sub i8 %s, %s\n", x, d8, s8)
		case "XORB":
			fmt.Fprintf(c.b, "  %%%s = xor i8 %s, %s\n", x, d8, s8)
		case "ANDB":
			fmt.Fprintf(c.b, "  %%%s = and i8 %s, %s\n", x, d8, s8)
		case "ORB":
			fmt.Fprintf(c.b, "  %%%s = or i8 %s, %s\n", x, d8, s8)
		}
		if err := storeDst("%" + x); err != nil {
			return true, false, err
		}
		switch op {
		case "ADDB":
			d16 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", d16, d8)
			s16 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i8 %s to i16\n", s16, s8)
			total := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = add i16 %%%s, %%%s\n", total, d16, s16)
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i16 %%%s, 255\n", cf, total)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		case "SUBB":
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i8 %s, %s\n", cf, d8, s8)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		default:
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		if op == "ADDB" || op == "SUBB" {
			x1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i8 %s, %s\n", x1, d8, s8)
			if op == "ADDB" {
				nx1 := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = xor i8 %%%s, -1\n", nx1, x1)
				x1 = nx1
			}
			x2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i8 %s, %%%s\n", x2, d8, x)
			x3 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, %%%s\n", x3, x1, x2)
			of := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", of, x3)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", of, c.flagsOFSlot)
		} else {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		}
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i8 %%%s, 0\n", zf, x)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i8 %%%s, 0\n", sf, x)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		return true, false, nil

	case "ANDW", "ORW", "XORW", "ADDW", "SUBW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], I16)
		if err != nil {
			return true, false, err
		}
		dst, storeDst, err := c.loadIntDestination(ins.Args[1], I16)
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		switch op {
		case "ANDW":
			fmt.Fprintf(c.b, "  %%%s = and i16 %s, %s\n", out, dst, src)
		case "ORW":
			fmt.Fprintf(c.b, "  %%%s = or i16 %s, %s\n", out, dst, src)
		case "XORW":
			fmt.Fprintf(c.b, "  %%%s = xor i16 %s, %s\n", out, dst, src)
		case "ADDW":
			fmt.Fprintf(c.b, "  %%%s = add i16 %s, %s\n", out, dst, src)
		case "SUBW":
			fmt.Fprintf(c.b, "  %%%s = sub i16 %s, %s\n", out, dst, src)
		}
		if err := storeDst("%" + out); err != nil {
			return true, false, err
		}
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %%%s, 0\n", zf, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		sf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i16 %%%s, 0\n", sf, out)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sf, c.flagsSltSlot)
		if op == "ADDW" {
			sum := c.newTmp()
			dst32 := c.newTmp()
			src32 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", dst32, dst)
			fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", src32, src)
			fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, %%%s\n", sum, dst32, src32)
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ugt i32 %%%s, 65535\n", cf, sum)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		} else if op == "SUBW" {
			cf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ult i16 %s, %s\n", cf, dst, src)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
		} else {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		return true, false, nil

	case "INCQ", "DECQ":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects dst: %q", op, ins.Raw)
		}
		var v string
		var storeDst func(string) error
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			dv, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			v = dv
			storeDst = func(out string) error { return c.storeReg(r, out) }
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s, align 1\n", ld, p)
			v = "%" + ld
			storeDst = func(out string) error {
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", out, p)
				return nil
			}
		case OpFP:
			var err error
			v, storeDst, err = c.loadIntDestination(ins.Args[0], I64)
			if err != nil {
				return true, false, err
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}
		t := c.newTmp()
		if op == "INCQ" {
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, 1\n", t, v)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i64 %s, 1\n", t, v)
		}
		out := "%" + t
		if err := storeDst(out); err != nil {
			return true, false, err
		}
		c.setZSFlagsFromI64(out)
		return true, false, nil

	case "INCL", "DECL":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects dst: %q", op, ins.Raw)
		}
		var v64 string
		var storeDst func(string) error
		switch ins.Args[0].Kind {
		case OpReg:
			r := ins.Args[0].Reg
			dv, err := c.loadReg(r)
			if err != nil {
				return true, false, err
			}
			v64 = dv
			storeDst = func(out32 string) error {
				z := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", z, out32)
				return c.storeReg(r, "%"+z)
			}
		case OpMem:
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			p := c.ptrFromAddrI64(addr)
			ld := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, ptr %s, align 1\n", ld, p)
			v64 = "%" + ld
			storeDst = func(out32 string) error {
				fmt.Fprintf(c.b, "  store i32 %s, ptr %s, align 1\n", out32, p)
				return nil
			}
		case OpFP:
			var err error
			v64, storeDst, err = c.loadIntDestination(ins.Args[0], I32)
			if err != nil {
				return true, false, err
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg/mem dst: %q", op, ins.Raw)
		}
		tr := c.newTmp()
		if ins.Args[0].Kind == OpMem || ins.Args[0].Kind == OpFP {
			fmt.Fprintf(c.b, "  %%%s = add i32 0, %s\n", tr, v64)
		} else {
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		}
		x := c.newTmp()
		if op == "INCL" {
			fmt.Fprintf(c.b, "  %%%s = add i32 %%%s, 1\n", x, tr)
		} else {
			fmt.Fprintf(c.b, "  %%%s = sub i32 %%%s, 1\n", x, tr)
		}
		if err := storeDst("%" + x); err != nil {
			return true, false, err
		}
		c.setZSFlagsFromI32("%" + x)
		return true, false, nil

	case "LEAW", "LEAL", "LEAQ":
		// All three widths use Go 1.27's sole ym_rl row: an addressable
		// memory expression and an in-range general-register destination.
		if op == "LEAQ" && c.goarch == "386" {
			return true, false, fmt.Errorf("386 LEAQ is illegal in 32-bit mode: %q", ins.Raw)
		}
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s expects Ym address and Yrl destination: %q", c.goarch, op, ins.Raw)
		}
		dst := ins.Args[1].Reg
		storeLEA := func(addr string) error {
			switch op {
			case "LEAW":
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i16\n", t, addr)
				return c.storeRegSized(dst, I16, "%"+t)
			case "LEAL":
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", t, addr)
				return c.storeRegSized(dst, I32, "%"+t)
			default:
				return c.storeRegSized(dst, I64, addr)
			}
		}
		switch ins.Args[0].Kind {
		case OpMem:
			if !x86MemoryRegistersValidForArch(ins.Args[0].Mem, c.goarch) {
				return true, false, fmt.Errorf("%s %s source uses an out-of-range address register: %q", c.goarch, op, ins.Raw)
			}
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			return true, false, storeLEA(addr)
		case OpFP:
			if c.classicFrame != "" {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				addr := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", addr, c.classicFramePtr(ins.Args[0].FPOffset))
				return true, false, storeLEA("%" + addr)
			}
			// LEA of a return slot, e.g. "LEAQ ret+32(FP), R8".
			alloca, _, ok := c.fpResultAlloca(ins.Args[0].FPOffset)
			if ok {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, alloca)
				return true, false, storeLEA("%" + t)
			}
			// Fallback: treat FP slot value as pointer-like integer address.
			v, err := c.evalFPToI64(ins.Args[0].FPOffset)
			if err != nil {
				v = "0"
			}
			return true, false, storeLEA(v)
		case OpFPAddr:
			if c.classicFrame != "" {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				addr := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", addr, c.classicFramePtr(ins.Args[0].FPOffset))
				return true, false, storeLEA("%" + addr)
			}
			// Address of a return slot alloca.
			alloca, _, ok := c.fpResultAlloca(ins.Args[0].FPOffset)
			if ok {
				c.markFPResultAddrTaken(ins.Args[0].FPOffset)
				t := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, alloca)
				return true, false, storeLEA("%" + t)
			}
			v, err := c.evalFPToI64(ins.Args[0].FPOffset)
			if err != nil {
				v = "0"
			}
			return true, false, storeLEA(v)
		case OpSym:
			p, err := c.ptrFromSB(ins.Args[0].Sym)
			if err != nil {
				return true, false, err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", t, p)
			return true, false, storeLEA("%" + t)
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported src: %q", op, ins.Raw)
		}

	case "POPCNTW", "POPCNTL", "POPCNTQ":
		// All three widths use Go 1.27's yml_rl table: a Yml GP-or-memory
		// source and a Yrl GP destination. POPCNTQ requires 64-bit mode.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		if op == "POPCNTQ" && c.goarch != "amd64" {
			return true, false, fmt.Errorf("amd64 %s requires GOARCH=amd64: %q", op, ins.Raw)
		}
		validFullReg := func(r Reg) bool {
			return isX86YrlRegisterForArch(r, c.goarch)
		}
		if !validFullReg(ins.Args[1].Reg) {
			return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's Yrl class: %q", op, ins.Raw)
		}
		src := ins.Args[0]
		switch src.Kind {
		case OpReg:
			if !validFullReg(src.Reg) {
				return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's Yml class: %q", op, ins.Raw)
			}
		case OpMem, OpFP, OpSym:
		default:
			return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's Yml class: %q", op, ins.Raw)
		}
		bits := 64
		typ := I64
		switch op {
		case "POPCNTW":
			bits, typ = 16, I16
		case "POPCNTL":
			bits, typ = 32, I32
		}
		srcv, err := c.evalIntSized(src, typ)
		if err != nil {
			return true, false, err
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.ctpop.i%d(i%d %s)\n", call, bits, bits, bits, srcv)
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %s, 0\n", zero, bits, srcv)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		return true, false, c.storeRegSized(ins.Args[1].Reg, typ, "%"+call)

	case "TZCNTW", "TZCNTL", "TZCNTQ":
		// All widths share Go 1.27's ycrc32l table: Yml source and Yrl
		// destination. TZCNTQ requires 64-bit mode.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		if op == "TZCNTQ" && c.goarch != "amd64" {
			return true, false, fmt.Errorf("amd64 TZCNTQ requires GOARCH=amd64: %q", ins.Raw)
		}
		if !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
			return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's Yrl class: %q", op, ins.Raw)
		}
		source := ins.Args[0]
		if source.Kind == OpReg {
			if !isX86YrlRegisterForArch(source.Reg, c.goarch) {
				return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's Yml class: %q", op, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s source is outside Go 1.27's Yml class: %q", op, ins.Raw)
		}
		bits := 64
		typ := I64
		switch op {
		case "TZCNTW":
			bits, typ = 16, I16
		case "TZCNTL":
			bits, typ = 32, I32
		}
		sourceValue, err := c.evalIntSized(source, typ)
		if err != nil {
			return true, false, err
		}
		count := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.cttz.i%d(i%d %s, i1 false)\n", count, bits, bits, bits, sourceValue)
		carry := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %s, 0\n", carry, bits, sourceValue)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", zero, bits, count)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
		return true, false, c.storeRegSized(ins.Args[1].Reg, typ, "%"+count)

	case "BSFW", "BSRW":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		src, err := c.evalIntSized(ins.Args[0], I16)
		if err != nil {
			return true, false, err
		}
		zf := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %s, 0\n", zf, src)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
		ext := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i16 %s to i32\n", ext, src)
		var result string
		if op == "BSFW" {
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.cttz.i32(i32 %%%s, i1 false)\n", call, ext)
			result = "%" + call
		} else {
			clz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %%%s, i1 false)\n", clz, ext)
			sub := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 31, %%%s\n", sub, clz)
			result = "%" + sub
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i32 %s to i16\n", tr, result)
		return true, false, c.storeRegSized(ins.Args[1].Reg, I16, "%"+tr)

	case "BSFQ", "BSRQ", "BSWAPQ", "BSFL", "BSRL":
		// Bit scans accept register or memory sources. BSWAPQ is register-only.
		sv := ""
		dst := Reg("")
		switch len(ins.Args) {
		case 1:
			if op != "BSWAPQ" || ins.Args[0].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s expects reg or srcReg,dstReg: %q", op, ins.Raw)
			}
			dst = ins.Args[0].Reg
			var err error
			sv, err = c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
		case 2:
			if op == "BSWAPQ" || ins.Args[1].Kind != OpReg {
				return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
			}
			dst = ins.Args[1].Reg
			srcType := I64
			if op == "BSFL" || op == "BSRL" {
				srcType = I32
			}
			var err error
			sv, err = c.evalIntSized(ins.Args[0], srcType)
			if err != nil {
				return true, false, err
			}
		default:
			return true, false, fmt.Errorf("amd64 %s expects 1 or 2 operands: %q", op, ins.Raw)
		}
		switch op {
		case "BSFQ":
			// ZF is set when src == 0.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = cttz(src). Use non-poison form for src==0.
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.cttz.i64(i64 %s, i1 false)\n", call, sv)
			return true, false, c.storeReg(dst, "%"+call)
		case "BSRQ":
			// ZF is set when src == 0.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = 63 - ctlz(src). Use non-poison form for src==0.
			clz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctlz.i64(i64 %s, i1 false)\n", clz, sv)
			sub := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 63, %%%s\n", sub, clz)
			return true, false, c.storeReg(dst, "%"+sub)
		case "BSWAPQ":
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.bswap.i64(i64 %s)\n", call, sv)
			return true, false, c.storeReg(dst, "%"+call)
		case "BSFL":
			// ZF is set when the 32-bit source is zero.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = zext(cttz(src)). Use non-poison form for src==0.
			call := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.cttz.i32(i32 %s, i1 false)\n", call, sv)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
			return true, false, c.storeReg(dst, "%"+z)
		case "BSRL":
			// ZF is set when the 32-bit source is zero.
			zf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %s, 0\n", zf, sv)
			fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zf, c.flagsZSlot)
			// dst = zext(31 - ctlz(src)). Use non-poison form for src==0.
			clz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.ctlz.i32(i32 %s, i1 false)\n", clz, sv)
			sub := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i32 31, %%%s\n", sub, clz)
			z := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sub)
			return true, false, c.storeReg(dst, "%"+z)
		}
		return true, false, fmt.Errorf("amd64: unsupported bit op %s", op)

	case "SETEQ", "SETLT", "SETGT", "SETGE", "SETHI", "SETCS":
		// SETcc dst: set byte based on flags.
		// Register, memory, and FP result destinations all occur in Go's x86
		// assembly sources.
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("amd64 %s expects one destination: %q", op, ins.Raw)
		}
		cond := ""
		switch op {
		case "SETEQ":
			cond, err = c.x86Condition("EQ")
		case "SETLT":
			cond, err = c.x86Condition("LT")
		case "SETGT":
			cond, err = c.x86Condition("GT")
		case "SETGE":
			cond, err = c.x86Condition("GE")
		case "SETHI":
			cond, err = c.x86Condition("HI")
		case "SETCS":
			cond, err = c.x86Condition("CS")
		}
		if err != nil {
			return true, false, err
		}
		switch ins.Args[0].Kind {
		case OpReg:
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", sel, cond)
			return true, false, c.storeRegSized(ins.Args[0].Reg, I8, "%"+sel)
		case OpFP:
			return true, false, c.storeFPResult(ins.Args[0].FPOffset, I1, cond)
		case OpMem:
			p, ptrType, err := c.ptrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			sel := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i8 1, i8 0\n", sel, cond)
			fmt.Fprintf(c.b, "  store i8 %%%s, %s %s, align 1\n", sel, ptrType, p)
			return true, false, nil
		default:
			return true, false, fmt.Errorf("amd64 %s expects reg, mem, or fp destination: %q", op, ins.Raw)
		}

	case "CMOVQEQ", "CMOVQNE", "CMOVQCS", "CMOVQCC", "CMOVQGT", "CMOVQLE", "CMOVLGT", "CMOVWCC":
		// Conditional move: src, dstReg
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects src, dstReg: %q", op, ins.Raw)
		}
		ty := I64
		if op == "CMOVLGT" {
			ty = I32
		} else if op == "CMOVWCC" {
			ty = I16
		}
		src, err := c.evalIntSized(ins.Args[0], ty)
		if err != nil {
			return true, false, err
		}
		dst := ins.Args[1].Reg
		cur, err := c.evalIntSized(ins.Args[1], ty)
		if err != nil {
			return true, false, err
		}
		cond := ""
		switch op {
		case "CMOVQEQ":
			cond = c.loadFlag(c.flagsZSlot)
		case "CMOVQNE":
			z := c.loadFlag(c.flagsZSlot)
			nz := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", nz, z)
			cond = "%" + nz
		case "CMOVQCS":
			cond = c.loadFlag(c.flagsCFSlot)
		case "CMOVQCC", "CMOVWCC":
			cf := c.loadFlag(c.flagsCFSlot)
			nc := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", nc, cf)
			cond = "%" + nc
		case "CMOVQGT", "CMOVLGT":
			slt := c.loadFlag(c.flagsSltSlot)
			z := c.loadFlag(c.flagsZSlot)
			t1 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t1, slt, z)
			t2 := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", t2, t1)
			cond = "%" + t2
		case "CMOVQLE":
			slt := c.loadFlag(c.flagsSltSlot)
			z := c.loadFlag(c.flagsZSlot)
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", t, slt, z)
			cond = "%" + t
		}
		sel := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, %s %s, %s %s\n", sel, cond, ty, src, ty, cur)
		return true, false, c.storeRegSized(dst, ty, "%"+sel)

	case "ANDNL", "ANDNQ":
		// BMI1 ANDN: destination = ~second & first. Go's _yandnl table
		// accepts Yml,Yrl,Yrl for both spellings. VEX.W is ignored in 386.
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) || ins.Args[2].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[2].Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s expects GP/memory source, GP source, GP destination: %q", c.goarch, op, ins.Raw)
		}
		if ins.Args[0].Kind == OpReg {
			if !isX86YrlRegisterForArch(ins.Args[0].Reg, c.goarch) {
				return true, false, fmt.Errorf("%s %s first source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s first source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
		typ := I32
		if op == "ANDNQ" && c.goarch == "amd64" {
			typ = I64
		}
		first, err := c.evalIntSized(ins.Args[0], typ)
		if err != nil {
			return true, false, err
		}
		second, err := c.evalIntSized(ins.Args[1], typ)
		if err != nil {
			return true, false, err
		}
		inverted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, -1\n", inverted, typ, second)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", result, typ, inverted, first)
		if typ == I64 {
			c.setZSFlagsFromI64("%" + result)
		} else {
			c.setZSFlagsFromI32("%" + result)
		}
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		return true, false, c.storeRegSized(ins.Args[2].Reg, typ, "%"+result)

	case "SHRQ", "SHLQ", "SARQ", "SHLL", "SHRL", "SARL", "SALQ", "SALL":
		// Shift ops:
		// - 2-operand: amt, dst (in-place)
		// - 3-operand SHL/SHR: amt, src, dst (x86 SHLD/SHRD)
		if len(ins.Args) == 3 {
			switch op {
			case "SHLL", "SHLQ", "SHRL", "SHRQ":
				return true, false, c.lowerDoubleShift(op, ins)
			default:
				return true, false, fmt.Errorf("amd64 %s has no three-operand form: %q", op, ins.Raw)
			}
		}
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects amt,dst: %q", op, ins.Raw)
		}
		if ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s destination must be reg: %q", op, ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		amtMask := int64(63)
		valTy := I64
		if op == "SHLL" || op == "SHRL" || op == "SARL" || op == "SALL" {
			amtMask = 31
			valTy = I32
		}
		amtI64 := ""
		switch ins.Args[0].Kind {
		case OpImm:
			amtI64 = fmt.Sprintf("%d", ins.Args[0].Imm&amtMask)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", m, av, amtMask)
			amtI64 = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported shift amt: %q", op, ins.Raw)
		}

		if valTy == I64 {
			t := c.newTmp()
			switch op {
			case "SHRQ":
				fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", t, dv, amtI64)
			case "SHLQ", "SALQ":
				fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", t, dv, amtI64)
			case "SARQ":
				fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %s\n", t, dv, amtI64)
			}
			return true, false, c.storeReg(dst, "%"+t)
		}

		// 32-bit shifts: operate on low 32, zero-extend to 64.
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, dv)
		amt32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", amt32, amtI64)
		sh := c.newTmp()
		if op == "SHLL" || op == "SALL" {
			fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", sh, tr, amt32)
		} else if op == "SARL" {
			fmt.Fprintf(c.b, "  %%%s = ashr i32 %%%s, %%%s\n", sh, tr, amt32)
		} else {
			fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %%%s\n", sh, tr, amt32)
		}
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, sh)
		return true, false, c.storeReg(dst, "%"+z)

	case "SHLW", "SHRW", "SARW", "SALW":
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s expects amt, dstReg: %q", op, ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.evalIntSized(ins.Args[1], I16)
		if err != nil {
			return true, false, err
		}
		var amt string
		switch ins.Args[0].Kind {
		case OpImm:
			amt = fmt.Sprintf("%d", ins.Args[0].Imm&31)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 31\n", masked, av)
			amt = "%" + masked
		default:
			return true, false, fmt.Errorf("amd64 %s unsupported shift amt: %q", op, ins.Raw)
		}
		inRange := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, 16\n", inRange, amt)
		safeAmt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 15\n", safeAmt, inRange, amt)
		amt16 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i16\n", amt16, safeAmt)
		shifted := c.newTmp()
		switch op {
		case "SHLW", "SALW":
			fmt.Fprintf(c.b, "  %%%s = shl i16 %s, %%%s\n", shifted, dv, amt16)
		case "SARW":
			fmt.Fprintf(c.b, "  %%%s = ashr i16 %s, %%%s\n", shifted, dv, amt16)
		case "SHRW":
			fmt.Fprintf(c.b, "  %%%s = lshr i16 %s, %%%s\n", shifted, dv, amt16)
		}
		result := "%" + shifted
		if op != "SARW" {
			out := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 0\n", out, inRange, shifted)
			result = "%" + out
		}
		return true, false, c.storeRegSized(dst, I16, result)

	case "SHLB":
		// 8-bit logical left shift: amt, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 SHLB expects amt, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		d8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i8\n", d8, dv64)
		var amt string
		switch ins.Args[0].Kind {
		case OpImm:
			amt = fmt.Sprintf("%d", ins.Args[0].Imm&31)
		case OpReg:
			av, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 31\n", m, av)
			amt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 SHLB unsupported shift amt: %q", ins.Raw)
		}
		inRange := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, 8\n", inRange, amt)
		safeAmt := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 7\n", safeAmt, inRange, amt)
		amt8 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", amt8, safeAmt)
		sh := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i8 %%%s, %%%s\n", sh, d8, amt8)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 %%%s, i8 0\n", out, inRange, sh)
		return true, false, c.storeRegSized(dst, I8, "%"+out)

	case "ROLL":
		// 32-bit rotate-left: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 ROLL expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		dv32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dv32, dv64)

		var cnt32 string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt32 = fmt.Sprintf("%d", uint32(ins.Args[0].Imm))
		case OpReg:
			cv64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, cv64)
			cnt32 = "%" + tr
		default:
			return true, false, fmt.Errorf("amd64 ROLL unsupported count: %q", ins.Raw)
		}

		cm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %s, 31\n", cm, cnt32)
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %%%s\n", neg, cm)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", lhs, dv32, cm)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %%%s\n", rhs, dv32, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "ROLQ":
		// 64-bit rotate-left: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 ROLQ expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		var cnt string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt = fmt.Sprintf("%d", uint64(ins.Args[0].Imm)&63)
		case OpReg:
			cv, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, cv)
			cnt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 ROLQ unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %s\n", neg, cnt)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %s\n", lhs, dv, cnt)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %%%s\n", rhs, dv, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
		return true, false, c.storeReg(dst, "%"+rot)

	case "RORQ":
		// 64-bit rotate-right: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 RORQ expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		var cnt string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt = fmt.Sprintf("%d", uint64(ins.Args[0].Imm)&63)
		case OpReg:
			cv, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			m := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, 63\n", m, cv)
			cnt = "%" + m
		default:
			return true, false, fmt.Errorf("amd64 RORQ unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i64 64, %s\n", neg, cnt)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %s\n", lhs, dv, cnt)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", rhs, dv, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
		return true, false, c.storeReg(dst, "%"+rot)

	case "RORL":
		// 32-bit rotate-right: count, dstReg.
		if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 RORL expects count, dstReg: %q", ins.Raw)
		}
		dst := ins.Args[1].Reg
		dv64, err := c.loadReg(dst)
		if err != nil {
			return true, false, err
		}
		dv32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dv32, dv64)
		var cnt32 string
		switch ins.Args[0].Kind {
		case OpImm:
			cnt32 = fmt.Sprintf("%d", uint32(ins.Args[0].Imm)&31)
		case OpReg:
			cv64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			tr := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, cv64)
			cm := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", cm, tr)
			cnt32 = "%" + cm
		default:
			return true, false, fmt.Errorf("amd64 RORL unsupported count: %q", ins.Raw)
		}
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %s\n", neg, cnt32)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %%%s, %s\n", lhs, dv32, cnt32)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %%%s, %%%s\n", rhs, dv32, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "RORXL", "RORXQ":
		// BMI2 rotate-right without flags. Go's Yml source class accepts a
		// general register or every ModRM/SIB memory form; Yrl is the complete
		// destination class. In 386 mode Go accepts the Q spelling too, but
		// VEX.W is ignored and the architectural operation remains 32-bit.
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[2].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[2].Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s expects $imm, GP/memory source, in-range GP destination: %q", c.goarch, op, ins.Raw)
		}
		if ins.Args[1].Kind == OpReg {
			if !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
				return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
			}
		} else if !isAMD64MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
		}
		dst := ins.Args[2].Reg
		if op == "RORXQ" && c.goarch == "amd64" {
			src, err := c.evalIntSized(ins.Args[1], I64)
			if err != nil {
				return true, false, err
			}
			n := uint64(ins.Args[0].Imm) & 63
			neg := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sub i64 64, %d\n", neg, n)
			nm := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", nm, neg)
			lhs := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", lhs, src, n)
			rhs := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", rhs, src, nm)
			rot := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rot, lhs, rhs)
			return true, false, c.storeReg(dst, "%"+rot)
		}
		src, err := c.evalIntSized(ins.Args[1], I32)
		if err != nil {
			return true, false, err
		}
		n := uint32(ins.Args[0].Imm) & 31
		neg := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub i32 32, %d\n", neg, n)
		nm := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 31\n", nm, neg)
		lhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, %d\n", lhs, src, n)
		rhs := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i32 %s, %%%s\n", rhs, src, nm)
		rot := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i32 %%%s, %%%s\n", rot, lhs, rhs)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, rot)
		return true, false, c.storeReg(dst, "%"+z)

	case "BSWAPL":
		// BSWAPL reg: byte swap low 32 bits and zero-extend result to i64.
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 BSWAPL expects reg: %q", ins.Raw)
		}
		r := ins.Args[0].Reg
		v64, err := c.loadReg(r)
		if err != nil {
			return true, false, err
		}
		tr := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", tr, v64)
		bswap := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.bswap.i32(i32 %%%s)\n", bswap, tr)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, bswap)
		return true, false, c.storeReg(r, "%"+z)

	case "MULXL":
		// BMI2 MULXL src, loDst, hiDst multiplies the low 32 bits of DX by
		// a 32-bit register or memory source and zero-extends both results.
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 MULXL expects src, loDst, hiDst: %q", ins.Raw)
		}
		var src32 string
		switch ins.Args[0].Kind {
		case OpReg:
			src64, err := c.loadReg(ins.Args[0].Reg)
			if err != nil {
				return true, false, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", value, src64)
			src32 = "%" + value
		case OpMem:
			pointer, pointerType, err := c.ptrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i32, %s %s, align 1\n", value, pointerType, pointer)
			src32 = "%" + value
		default:
			return true, false, fmt.Errorf("amd64 MULXL source must be register or memory: %q", ins.Raw)
		}
		dx64, err := c.loadReg(DX)
		if err != nil {
			return true, false, err
		}
		dx32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", dx32, dx64)
		a64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", a64, dx32)
		b64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", b64, src32)
		product := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", product, a64, b64)
		lo32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", lo32, product)
		hiShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 32\n", hiShift, product)
		hi32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", hi32, hiShift)
		lo64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", lo64, lo32)
		hi64 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", hi64, hi32)
		if err := c.storeReg(ins.Args[1].Reg, "%"+lo64); err != nil {
			return true, false, err
		}
		if err := c.storeReg(ins.Args[2].Reg, "%"+hi64); err != nil {
			return true, false, err
		}
		return true, false, nil

	case "MULXQ":
		// BMI2 MULXQ src, loDst, hiDst: {hi,lo} = RDX * src (unsigned).
		if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("amd64 MULXQ expects src, loDst, hiDst: %q", ins.Raw)
		}
		src, err := c.evalI64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dx, err := c.loadReg(DX)
		if err != nil {
			return true, false, err
		}
		a128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", a128, dx)
		b128 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i64 %s to i128\n", b128, src)
		p := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i128 %%%s, %%%s\n", p, a128, b128)
		lo := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", lo, p)
		hiShift := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i128 %%%s, 64\n", hiShift, p)
		hi := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i128 %%%s to i64\n", hi, hiShift)
		if err := c.storeReg(ins.Args[1].Reg, "%"+lo); err != nil {
			return true, false, err
		}
		if err := c.storeReg(ins.Args[2].Reg, "%"+hi); err != nil {
			return true, false, err
		}
		return true, false, nil

	}
	return false, false, nil
}

func (c *amd64Ctx) lowerDoubleShift(op Op, ins Instr) error {
	if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg {
		return fmt.Errorf("amd64 %s expects amt, srcReg, dst: %q", op, ins.Raw)
	}
	ty := I64
	mask := int64(63)
	left := op == "SHLQ"
	if op == "SHLL" || op == "SHRL" {
		ty = I32
		mask = 31
		left = op == "SHLL"
	}

	src, err := c.evalIntSized(ins.Args[1], ty)
	if err != nil {
		return err
	}
	dst, storeDst, err := c.loadIntDestination(ins.Args[2], ty)
	if err != nil {
		return err
	}

	count64 := ""
	switch ins.Args[0].Kind {
	case OpImm:
		count64 = fmt.Sprintf("%d", ins.Args[0].Imm&mask)
	case OpReg:
		value, err := c.loadReg(ins.Args[0].Reg)
		if err != nil {
			return err
		}
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, value, mask)
		count64 = "%" + masked
	default:
		return fmt.Errorf("amd64 %s unsupported shift amount: %q", op, ins.Raw)
	}

	count := count64
	if ty == I32 {
		truncated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, count64)
		count = "%" + truncated
	}
	inverseNeg := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s 0, %s\n", inverseNeg, ty, count)
	inverse := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %d\n", inverse, ty, inverseNeg, mask)
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, ty, count)

	dstPart := c.newTmp()
	srcPart := c.newTmp()
	if left {
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %s\n", dstPart, ty, dst, count)
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %%%s\n", srcPart, ty, src, inverse)
	} else {
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", dstPart, ty, dst, count)
		fmt.Fprintf(c.b, "  %%%s = shl %s %s, %%%s\n", srcPart, ty, src, inverse)
	}
	merged := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", merged, ty, dstPart, srcPart)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, %s %s, %s %%%s\n", out, zero, ty, dst, ty, merged)
	return storeDst("%" + out)
}

func (c *amd64Ctx) lower386Timestamp(serialized bool) error {
	asm := "rdtsc"
	resultType := "{ i32, i32 }"
	constraints := "={ax},={dx},~{dirflag},~{fpsr},~{flags},~{memory}"
	regs := []Reg{AX, DX}
	if serialized {
		asm = "rdtscp"
		resultType = "{ i32, i32, i32 }"
		constraints = "={ax},={dx},={cx},~{dirflag},~{fpsr},~{flags},~{memory}"
		regs = append(regs, CX)
	}
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n", call, resultType, asm, constraints)
	for i, reg := range regs {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, resultType, call, i)
		if err := c.storeRegSized(reg, I32, "%"+value); err != nil {
			return err
		}
	}
	return nil
}
