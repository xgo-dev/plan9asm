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

type x86StatusFlagMask uint16

const (
	x86StatusCF  x86StatusFlagMask = 1 << 0
	x86StatusPF  x86StatusFlagMask = 1 << 2
	x86StatusAF  x86StatusFlagMask = 1 << 4
	x86StatusZF  x86StatusFlagMask = 1 << 6
	x86StatusSF  x86StatusFlagMask = 1 << 7
	x86StatusOF  x86StatusFlagMask = 1 << 11
	x86StatusAll                   = x86StatusCF | x86StatusPF | x86StatusAF | x86StatusZF | x86StatusSF | x86StatusOF
)

func (c *amd64Ctx) x86StatusFlagSlots() []x86FlagSlot {
	return []x86FlagSlot{
		{c.flagsCFSlot, 0},
		{c.flagsPFSlot, 2},
		{c.flagsAFSlot, 4},
		{c.flagsZSlot, 6},
		{c.flagsSltSlot, 7},
		{c.flagsOFSlot, 11},
	}
}

func (c *amd64Ctx) x86FlagSlots() []x86FlagSlot {
	flags := c.x86StatusFlagSlots()
	if c.directionSlot != "" {
		flags = append(flags, x86FlagSlot{c.directionSlot, 10})
	}
	if c.flagsIDSlot != "" {
		flags = append(flags, x86FlagSlot{c.flagsIDSlot, 21})
	}
	return flags
}

// Clear exactly the ISA-defined status bits. Reusing the complete slot model
// prevents a consumer's hand-written subset from silently omitting AF.
func (c *amd64Ctx) clearX86StatusFlags(mask x86StatusFlagMask) {
	for _, flag := range c.x86StatusFlagSlots() {
		if mask&(1<<flag.bit) != 0 {
			fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", flag.slot)
		}
	}
}

// The carry/borrow into bit 4 equals bit 4 of a XOR b XOR result. The final
// result includes any ADC/SBB carry input, so the same width-independent rule
// covers binary arithmetic, comparison, unary increment/decrement and exchange.
func (c *amd64Ctx) setAuxiliaryCarryFlag(typ LLVMType, a, b, result string) {
	xorOperands := c.newTmp()
	xorResult := c.newTmp()
	bit := c.newTmp()
	flag := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorOperands, typ, a, b)
	fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, %s\n", xorResult, typ, xorOperands, result)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 16\n", bit, typ, xorResult)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", flag, typ, bit)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", flag, c.flagsAFSlot)
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

func (c *amd64Ctx) unpackX86Flags(packed string, operandBits int) {
	for _, flag := range c.x86FlagSlots() {
		// A word pop replaces FLAGS, not the upper EFLAGS/RFLAGS bits.
		// In particular, the ID bit remains unchanged by POPFW.
		if flag.bit >= uint(operandBits) {
			continue
		}
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
	if known, terminated, err := c.lowerByteSwap(op, ins); known {
		return true, terminated, err
	}
	if known, terminated, err := c.lowerScalarBitScan(op, ins); known {
		return true, terminated, err
	}
	if ok, terminated, err := c.lowerX86CPUQuery(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerX86OrderingHint(op, ins); ok {
		return ok, terminated, err
	}
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
	if ok, terminated, err := c.lowerMULX(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerANDN(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerScalarBitCount(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerBMI2ShiftRotate(op, ins); ok {
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
		// A closed native MMX region owns its actual EMMS before generic
		// dispatch. Never turn an unbound physical tag-state operation into
		// a successful logical-register no-op.
		return true, false, fmt.Errorf("%w: EMMS needs its source-bound native MMX/x87 continuation", ErrProbeNeedsContext)
	case "UNDEF":
		return c.lowerX86UndefinedTrap(op, ins)
	case "RDTSC", "RDTSCP":
		return c.lowerX86Timestamp(op, ins)
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
		src, destination, err := c.evalScalarArithmeticSource(ins, I64)
		if err != nil {
			return true, false, err
		}
		loadDst := func() (string, func(string) error, error) {
			switch destination.Kind {
			case OpReg:
				dst := destination.Reg
				dv, err := c.loadReg(dst)
				if err != nil {
					return "", nil, err
				}
				return dv, func(v string) error { return c.storeReg(dst, v) }, nil
			case OpMem:
				addr, err := c.addrFromMem(destination.Mem)
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

	case "ADDL", "SUBL", "XORL", "ANDL", "ORL":
		// 32-bit arithmetic/logical ops: src, dst.
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		s32, destination, err := c.evalScalarArithmeticSource(ins, I32)
		if err != nil {
			return true, false, err
		}
		dtr, storeDst, err := c.loadIntDestination(destination, I32)
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
		s8, destination, err := c.evalScalarArithmeticSource(ins, I8)
		if err != nil {
			return true, false, err
		}
		d8, storeDst, err := c.loadIntDestination(destination, I8)
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
		c.setParityFlagSized(I8, "%"+x)
		return true, false, nil

	case "ANDW", "ORW", "XORW", "ADDW", "SUBW":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects src, dst: %q", op, ins.Raw)
		}
		src, destination, err := c.evalScalarArithmeticSource(ins, I16)
		if err != nil {
			return true, false, err
		}
		dst, storeDst, err := c.loadIntDestination(destination, I16)
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
		c.setParityFlagSized(I16, "%"+out)
		return true, false, nil

	case "LEAW", "LEAL", "LEAQ":
		// All three widths use Go 1.27's sole ym_rl row: an addressable
		// memory expression and an in-range general-register destination.
		if ins.Op != "" && Op(strings.ToUpper(string(ins.Op))) != op {
			return true, false, fmt.Errorf("%s LEA dispatch %q disagrees with instruction %q", c.goarch, op, ins.Op)
		}
		// Internal helpers may omit Instr.Op. Bind only this local copy so
		// grammar validation and destination emission use one identity; the
		// original source/caller instruction remains independently required.
		ins.Op = op
		ins = x86LEASourceInstruction(ins)
		if _, err := x86LEAOperandWidth(ins, c.goarch); err != nil {
			return true, false, err
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
			addr, err := c.addrFromMem(ins.Args[0].Mem)
			if err != nil {
				return true, false, err
			}
			if bits := ins.x86AddressBits; bits != 0 {
				// Address size is independent of the result register width.
				// Narrow the complete sum first, then zero-extend that effective
				// offset before W/L/Q destination preservation/extension.
				typ := I32
				if bits == 16 {
					typ = I16
				}
				low := c.truncI64(addr, typ)
				wide := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, typ, low)
				addr = "%" + wide
			}
			return true, false, storeLEA(addr)
		case OpFP:
			v, err := c.boundFPAddress(ins.Args[0].FPOffset)
			if err != nil {
				return true, false, err
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

	}
	return false, false, nil
}
