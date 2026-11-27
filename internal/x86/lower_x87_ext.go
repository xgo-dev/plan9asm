package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func isX87FCMOVOp(op asm.Op) bool {
	switch op {
	case "FCMOVB", "FCMOVBE", "FCMOVCC", "FCMOVCS", "FCMOVE", "FCMOVEQ",
		"FCMOVHI", "FCMOVLS", "FCMOVNB", "FCMOVNBE", "FCMOVNE", "FCMOVNU",
		"FCMOVU", "FCMOVUN":
		return true
	}
	return false
}

func (c *amd64Ctx) lowerX87Ext(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	if spec, found := x87ArithSpecs[op]; found {
		return true, false, c.lowerX87ExtArith(op, spec, ins)
	}
	if spec, found := x87CmpSpecs[op]; found {
		return true, false, c.lowerX87ExtCmp(op, spec, ins)
	}
	if cst, found := x87ConstSpecs[op]; found {
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		c.projectX87Status("0", 0x0200)
		if cst.SigCeil == "" {
			if cst.SigFloor == "0" && cst.SignExp == "0" {
				return true, false, c.pushX87Value(x87ZeroValue)
			}
			return true, false, c.pushX87Value(c.packX87(cst.SigFloor, cst.SignExp))
		}
		if c.useHardwareX87() {
			c.emitX87NativeAsm(cst.HWInst+"; fstpt $0",
				[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}}, nil)
			return true, false, c.pushX87Value(x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0])))
		}
		// X87Software: honor live x87 control word RC (bits 11:10):
		// RD (1) and RZ (3) select SigFloor; RU (2) selects SigCeil;
		// RN (0) selects SigCeil iff cst.RNRoundsUp (FLDPI/FLDL2E/FLDLG2/FLDLN2),
		// or SigFloor for FLDL2T.
		cw := c.loadX87ControlWord()
		rc := c.x87IR("and i16 %s, 3", c.x87IR("lshr i16 %s, 10", cw))
		useCeil := c.x87IR("icmp eq i16 %s, 2", rc)
		if cst.RNRoundsUp {
			useCeil = c.x87IR("or i1 %s, %s", useCeil, c.x87IR("icmp eq i16 %s, 0", rc))
		}
		sig := c.x87IR("select i1 %s, i64 %s, i64 %s", useCeil, cst.SigCeil, cst.SigFloor)
		return true, false, c.pushX87Value(c.packX87(sig, cst.SignExp))
	}
	if reason, found := x87UnsupportedReasons[op]; found {
		return true, false, fmt.Errorf("%s: unsupported instruction %s (%s): %q", c.goarch, op, reason, ins.Raw)
	}
	if isX87FCMOVOp(op) {
		return true, false, c.lowerX87ExtFCMOV(op, ins)
	}
	switch op {
	case "FMOVF", "FMOVFP":
		return true, false, c.lowerX87ExtMovF32(op == "FMOVFP", ins)
	case "FMOVL", "FMOVLP":
		return true, false, c.lowerX87ExtMovInt(32, op == "FMOVLP", ins)
	case "FMOVW", "FMOVWP":
		return true, false, c.lowerX87ExtMovInt(16, op == "FMOVWP", ins)
	case "FMOVB", "FMOVBP":
		// Go's Plan 9 assembler encodes FMOVB mem, F0 as FBLD m80bcd (DF /4)
		// and FMOVBP F0, mem as FBSTP m80bcd (DF /6).
		return true, false, c.lowerX87ExtBCD(op == "FMOVBP", ins)
	case "FMOVX", "FMOVXP":
		return true, false, c.lowerX87ExtMovExt80(op == "FMOVXP", ins)
	case "FBLD", "FBSTP":
		return true, false, c.lowerX87ExtBCD(op == "FBSTP", ins)
	case "FFREE":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("386 FFREE expects x87 reg: %q", ins.Raw)
		}
		idx, ok := x87OperandReg(ins.Args[0])
		if !ok {
			return true, false, fmt.Errorf("386 FFREE expects x87 reg: %q", ins.Raw)
		}
		c.storeX87Value(idx, x87ZeroValue)
		return true, false, nil
	case "FINCSTP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FINCSTP takes no operands: %q", ins.Raw)
		}
		top := c.loadX87Value(0)
		for i := 0; i < len(c.x87Slot)-1; i++ {
			c.storeX87Value(i, c.loadX87Value(i+1))
		}
		c.storeX87Value(len(c.x87Slot)-1, top)
		c.adjustX87Top(1)
		c.projectX87Status("0", 0x0200)
		return true, false, nil
	case "FDECSTP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FDECSTP takes no operands: %q", ins.Raw)
		}
		last := c.loadX87Value(len(c.x87Slot) - 1)
		for i := len(c.x87Slot) - 1; i > 0; i-- {
			c.storeX87Value(i, c.loadX87Value(i-1))
		}
		c.storeX87Value(0, last)
		c.adjustX87Top(-1)
		c.projectX87Status("0", 0x0200)
		return true, false, nil
	}
	return false, false, nil
}

func (c *amd64Ctx) x87MemPtr(op asm.Operand) (string, string, error) {
	switch op.Kind {
	case asm.OpMem:
		return c.ptrFromMem(op.Mem)
	case asm.OpSym:
		p, err := c.ptrFromSB(op.Sym)
		return p, "ptr", err
	default:
		return "", "", fmt.Errorf("386 x87: expected memory operand, got %s", op.String())
	}
}

func (c *amd64Ctx) evalX87TypedValue(op asm.Operand, memKind string) (x87Value, error) {
	if idx, ok := x87OperandReg(op); ok {
		return c.loadX87Value(idx), nil
	}
	switch memKind {
	case "f64":
		f64, err := c.evalF64(op)
		if err != nil {
			return "", err
		}
		return c.f64ToX87Value(f64)
	case "f32":
		f32, err := c.evalF32(op)
		if err != nil {
			return "", err
		}
		if c.useHardwareX87() {
			return c.x87NativeFromScalar(f32, "float", "flds"), nil
		}
		return c.x87PortableFromFloat(f32, 32)
	case "i32":
		iv, err := c.evalIntSized(op, asm.I32)
		if err != nil {
			return "", err
		}
		if c.useHardwareX87() {
			return c.x87NativeFromScalar(iv, "i32", "fildl"), nil
		}
		return c.x87PortableFromSigned(iv, 32)
	default: // i16
		iv, err := c.evalIntSized(op, asm.I16)
		if err != nil {
			return "", err
		}
		if c.useHardwareX87() {
			return c.x87NativeFromScalar(iv, "i16", "filds"), nil
		}
		return c.x87PortableFromSigned(iv, 16)
	}
}

func (c *amd64Ctx) lowerX87ExtArith(op asm.Op, spec x87ArithSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects src, dst: %q", op, ins.Raw)
	}
	src, err := c.evalX87TypedValue(ins.Args[0], spec.memKind)
	if err != nil {
		return err
	}
	dst, err := c.evalX87Value(ins.Args[1])
	if err != nil {
		return err
	}
	lhs, rhs := dst, src
	if spec.rev {
		lhs, rhs = src, dst
	}
	var res x87Value
	if c.useHardwareX87() {
		// Execute in true 80-bit extended x87 precision using the live x87
		// control word (precision + rounding mode). evaluateX87Native pushes
		// inputs[1] (lhs) into ST(1) and inputs[0] (rhs) into ST(0).
		// Note AT&T mnemonic convention: fsubrp = [0xde,0xe9] = ST(1)-ST(0),
		// fdivrp = [0xde,0xf9] = ST(1)/ST(0).
		var hwOp string
		switch spec.llvmOp {
		case "fadd":
			hwOp = "faddp"
		case "fmul":
			hwOp = "fmulp"
		case "fsub":
			hwOp = "fsubrp"
		default: // fdiv
			hwOp = "fdivrp"
		}
		var status string
		res, _, status = c.evaluateX87Native(hwOp, []x87Value{rhs, lhs}, 1, 1)
		c.mergeX87ArithStatus(status)
	} else {
		// Execute in bit-exact IEEE-754 binary80 pure-integer software arithmetic
		// honoring live RC (rounding mode) and PC (precision control) in x87ControlSlot,
		// and record raised x87 exception flags + C1 into x87StatusSlot.
		var status string
		res, status = c.x87PortableArith(spec.llvmOp, lhs, rhs, c.loadX87ControlWord())
		c.mergeX87ArithStatus(status)
	}
	if dstIdx, ok := x87OperandReg(ins.Args[1]); ok {
		c.storeX87Value(dstIdx, res)
	} else {
		f64, err := c.x87ValueToF64(res)
		if err != nil {
			return err
		}
		if err := c.storeX87F64(ins.Args[1], f64); err != nil {
			return err
		}
	}
	if spec.pop {
		c.popX87Value()
	}
	return nil
}

func (c *amd64Ctx) lowerX87ExtCmp(op asm.Op, spec x87CmpSpec, ins asm.Instr) error {
	var lhsOp, rhsOp asm.Operand
	switch len(ins.Args) {
	case 0:
		lhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F0"}
		rhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F1"}
	case 1:
		lhsOp = asm.Operand{Kind: asm.OpReg, Reg: "F0"}
		rhsOp = ins.Args[0]
	case 2:
		// Plan 9 FCOM* src, F0 compares F0 against src; FCOMI/FUCOMI Fi, F0 compares F0 against Fi.
		if idx, ok := x87OperandReg(ins.Args[1]); ok && idx == 0 {
			lhsOp, rhsOp = ins.Args[1], ins.Args[0]
		} else {
			lhsOp, rhsOp = ins.Args[0], ins.Args[1]
		}
	default:
		return fmt.Errorf("386 %s expects 0..2 operands: %q", op, ins.Raw)
	}
	lhs, err := c.evalX87TypedValue(lhsOp, spec.memKind)
	if err != nil {
		return err
	}
	rhs, err := c.evalX87TypedValue(rhsOp, spec.memKind)
	if err != nil {
		return err
	}
	unorderedCmp := strings.HasPrefix(string(op), "FU")
	eq, lt, uno, exc := c.x87PortableCompareWithFlags(lhs, rhs, unorderedCmp)
	c.mergeX87StickyExceptions(exc)
	if spec.eflags {
		c.projectX87Status("0", 0x0200)
		z := c.x87IR("or i1 %s, %s", eq, uno)
		cf := c.x87IR("or i1 %s, %s", lt, uno)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", uno, c.flagsPFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		c.clearAuxCarryFlag()
	} else {
		c3 := c.x87IR("or i1 %s, %s", eq, uno)
		c0 := c.x87IR("or i1 %s, %s", lt, uno)
		c3w := c.x87IR("select i1 %s, i16 16384, i16 0", c3)
		c2w := c.x87IR("select i1 %s, i16 1024, i16 0", uno)
		c0w := c.x87IR("select i1 %s, i16 256, i16 0", c0)
		status := c.x87IR("or i16 %s, %s", c.x87IR("or i16 %s, %s", c3w, c2w), c0w)
		// Update C3|C2|C1|C0 (0x4700, with C1=0) while preserving TOP (0x3800).
		c.projectX87Status(status, 0x4700)
	}
	for i := 0; i < spec.pops; i++ {
		c.popX87Value()
	}
	return nil
}

func (c *amd64Ctx) lowerX87ExtFCMOV(op asm.Op, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects Fsrc, Fdst: %q", op, ins.Raw)
	}
	srcIdx, okS := x87OperandReg(ins.Args[0])
	dstIdx, okD := x87OperandReg(ins.Args[1])
	if !okS || !okD {
		return fmt.Errorf("386 %s expects x87 regs: %q", op, ins.Raw)
	}
	cf := c.x87IR("load i1, ptr %s", c.flagsCFSlot)
	zf := c.x87IR("load i1, ptr %s", c.flagsZSlot)
	pf := c.x87IR("load i1, ptr %s", c.flagsPFSlot)
	var cond string
	switch op {
	case "FCMOVB", "FCMOVCS":
		cond = cf
	case "FCMOVNB", "FCMOVCC":
		cond = c.x87IR("xor i1 %s, true", cf)
	case "FCMOVE", "FCMOVEQ":
		cond = zf
	case "FCMOVNE":
		cond = c.x87IR("xor i1 %s, true", zf)
	case "FCMOVBE", "FCMOVLS":
		cond = c.x87IR("or i1 %s, %s", cf, zf)
	case "FCMOVNBE", "FCMOVHI":
		cond = c.x87IR("xor i1 %s, true", c.x87IR("or i1 %s, %s", cf, zf))
	case "FCMOVU", "FCMOVUN":
		cond = pf
	default: // FCMOVNU
		cond = c.x87IR("xor i1 %s, true", pf)
	}
	sv := c.loadX87Value(srcIdx)
	dv := c.loadX87Value(dstIdx)
	sel := x87Value(c.x87IR("select i1 %s, %s %s, %s %s", cond, x87ValueType, sv, x87ValueType, dv))
	c.storeX87Value(dstIdx, sel)
	return nil
}

func (c *amd64Ctx) lowerX87ExtMovF32(pop bool, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects src, dst: %q", ins.Op, ins.Raw)
	}
	if srcIdx, ok := x87OperandReg(ins.Args[0]); ok {
		val := c.loadX87Value(srcIdx)
		var f32 string
		var err error
		if c.useHardwareX87() {
			f32 = c.x87NativeToScalar(val, "float", "fstps")
		} else {
			f32, err = c.x87PortableToFloat(val, 32, c.loadX87ControlWord())
			if err != nil {
				return err
			}
		}
		p, pty, err := c.x87MemPtr(ins.Args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store float %s, %s %s, align 1\n", f32, pty, p)
		if pop {
			c.popX87Value()
		}
		return nil
	}
	dstIdx, ok := x87OperandReg(ins.Args[1])
	if !ok {
		return fmt.Errorf("386 %s expects x87 reg operand: %q", ins.Op, ins.Raw)
	}
	f32, err := c.evalF32(ins.Args[0])
	if err != nil {
		return err
	}
	var x87v x87Value
	if c.useHardwareX87() {
		x87v = c.x87NativeFromScalar(f32, "float", "flds")
	} else {
		x87v, err = c.x87PortableFromFloat(f32, 32)
		if err != nil {
			return err
		}
	}
	if dstIdx == 0 {
		return c.pushX87Value(x87v)
	}
	c.storeX87Value(dstIdx, x87v)
	return nil
}

func (c *amd64Ctx) lowerX87ExtMovInt(bits int, pop bool, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects src, dst: %q", ins.Op, ins.Raw)
	}
	if srcIdx, ok := x87OperandReg(ins.Args[0]); ok {
		val := c.loadX87Value(srcIdx)
		convBits := bits
		if convBits == 8 {
			convBits = 16
		}
		var iv string
		var err error
		if c.useHardwareX87() {
			iv = c.x87NativeToSigned(val, convBits)
		} else {
			iv, err = c.x87PortableToSigned(val, convBits, c.loadX87ControlWord())
			if err != nil {
				return err
			}
		}
		if bits == 8 {
			iv = c.x87IR("trunc i16 %s to i8", iv)
		}
		p, pty, err := c.x87MemPtr(ins.Args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i%d %s, %s %s, align 1\n", bits, iv, pty, p)
		if pop {
			c.popX87Value()
		}
		return nil
	}
	dstIdx, ok := x87OperandReg(ins.Args[1])
	if !ok {
		return fmt.Errorf("386 %s expects x87 reg operand: %q", ins.Op, ins.Raw)
	}
	ty := x86LLVMIntType(uint16(bits))
	iv, err := c.evalIntSized(ins.Args[0], ty)
	if err != nil {
		return err
	}
	convBits := bits
	if bits == 8 {
		iv = c.x87IR("sext i8 %s to i16", iv)
		convBits = 16
	}
	x87v, err := c.x87PortableFromSigned(iv, convBits)
	if err != nil {
		return err
	}
	if dstIdx == 0 {
		return c.pushX87Value(x87v)
	}
	c.storeX87Value(dstIdx, x87v)
	return nil
}

func (c *amd64Ctx) lowerX87ExtMovExt80(pop bool, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects src, dst: %q", ins.Op, ins.Raw)
	}
	if srcIdx, ok := x87OperandReg(ins.Args[0]); ok {
		sig, se := c.partsX87(c.loadX87Value(srcIdx))
		p, pty, err := c.x87MemPtr(ins.Args[1])
		if err != nil {
			return err
		}
		p8 := c.x87IR("getelementptr i8, %s %s, i64 8", pty, p)
		fmt.Fprintf(c.b, "  store i64 %s, %s %s, align 1\n", sig, pty, p)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", se, p8)
		c.projectX87Status("0", 0x0200)
		if pop {
			c.popX87Value()
		}
		return nil
	}
	dstIdx, ok := x87OperandReg(ins.Args[1])
	if !ok {
		return fmt.Errorf("386 %s expects x87 reg operand: %q", ins.Op, ins.Raw)
	}
	p, pty, err := c.x87MemPtr(ins.Args[0])
	if err != nil {
		return err
	}
	p8 := c.x87IR("getelementptr i8, %s %s, i64 8", pty, p)
	sig := c.x87IR("load i64, %s %s, align 1", pty, p)
	se := c.x87IR("load i16, ptr %s, align 1", p8)
	v := c.packX87(sig, se)
	c.projectX87Status("0", 0x0200)
	if dstIdx == 0 {
		return c.pushX87Value(v)
	}
	c.storeX87Value(dstIdx, v)
	return nil
}

func (c *amd64Ctx) lowerX87ExtBCD(store bool, ins asm.Instr) error {
	var memOp asm.Operand
	switch len(ins.Args) {
	case 1:
		memOp = ins.Args[0]
	case 2:
		if !store {
			if idx, ok := x87OperandReg(ins.Args[1]); !ok || idx != 0 {
				return fmt.Errorf("386 %s expects mem, F0: %q", ins.Op, ins.Raw)
			}
			memOp = ins.Args[0]
		} else {
			if idx, ok := x87OperandReg(ins.Args[0]); !ok || idx != 0 {
				return fmt.Errorf("386 %s expects F0, mem: %q", ins.Op, ins.Raw)
			}
			memOp = ins.Args[1]
		}
	default:
		return fmt.Errorf("386 %s expects mem operand: %q", ins.Op, ins.Raw)
	}
	p, pty, err := c.x87MemPtr(memOp)
	if err != nil {
		return err
	}
	if !store {
		if c.useHardwareX87() {
			p8 := c.x87IR("getelementptr i8, %s %s, i64 8", pty, p)
			lo := c.x87IR("load i64, %s %s, align 1", pty, p)
			hi := c.x87IR("load i16, ptr %s, align 1", p8)
			fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, c.packX87(lo, hi), c.x87ValueScratch[1])
			c.emitX87NativeAsm("fbld $1; fstpt $0",
				[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}},
				[]x87NativeOperand{{c.x87ValueScratch[1], x87ValueType}})
			c.projectX87Status("0", 0x0200)
			return c.pushX87Value(x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0])))
		}
		// FBLD/FMOVB software mode: decode 18 packed BCD digits (bytes 0..8) + sign bit (byte 9 bit 7).
		acc := "0"
		for i := 8; i >= 0; i-- {
			pb := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, i)
			b := c.x87IR("zext i8 %s to i64", c.x87IR("load i8, ptr %s, align 1", pb))
			hi := c.x87IR("lshr i64 %s, 4", b)
			lo := c.x87IR("and i64 %s, 15", b)
			acc = c.x87IR("add i64 %s, %s", c.x87IR("mul i64 %s, 10", acc), hi)
			acc = c.x87IR("add i64 %s, %s", c.x87IR("mul i64 %s, 10", acc), lo)
		}
		p9 := c.x87IR("getelementptr i8, %s %s, i64 9", pty, p)
		sByte := c.x87IR("load i8, ptr %s, align 1", p9)
		neg := c.x87IR("icmp slt i8 %s, 0", sByte)
		val := c.x87IR("select i1 %s, i64 %s, i64 %s", neg, c.x87IR("sub i64 0, %s", acc), acc)
		x87v, err := c.i64ToX87Value(val)
		if err != nil {
			return err
		}
		// Preserve negative zero (-0.0) when sign bit is set and magnitude is 0.
		isNegZero := c.x87IR("and i1 %s, %s", neg, c.x87IR("icmp eq i64 %s, 0", acc))
		sig, se := c.partsX87(x87v)
		se = c.x87IR("select i1 %s, i16 -32768, i16 %s", isNegZero, se)
		return c.pushX87Value(c.packX87(sig, se))
	}
	if c.useHardwareX87() {
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, c.loadX87Value(0), c.x87ValueScratch[1])
		c.emitX87NativeAsm("fnclex; fldt $2; fbstp $0; fnstsw $1",
			[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}, {c.x87NativeStatus, "i16"}},
			[]x87NativeOperand{{c.x87ValueScratch[1], x87ValueType}})
		status := c.x87IR("load i16, ptr %s", c.x87NativeStatus)
		c.mergeX87ArithStatus(status)
		bcd := x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0]))
		lo, hi := c.partsX87(bcd)
		p8 := c.x87IR("getelementptr i8, %s %s, i64 8", pty, p)
		fmt.Fprintf(c.b, "  store i64 %s, %s %s, align 1\n", lo, pty, p)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", hi, p8)
		c.popX87Value()
		return nil
	}
	// FBSTP/FMOVBP software mode: encode signed i64 into 10-byte packed BCD and pop.
	val0 := c.loadX87Value(0)
	_, se0 := c.partsX87(val0)
	origNeg := c.x87IR("icmp slt i16 %s, 0", se0)
	iv, err := c.x87PortableToSigned(val0, 64, c.loadX87ControlWord())
	if err != nil {
		return err
	}
	neg := c.x87IR("or i1 %s, %s", c.x87IR("icmp slt i64 %s, 0", iv), c.x87IR("and i1 %s, %s", origNeg, c.x87IR("icmp eq i64 %s, 0", iv)))
	cur := c.x87IR("select i1 %s, i64 %s, i64 %s", c.x87IR("icmp slt i64 %s, 0", iv), c.x87IR("sub i64 0, %s", iv), iv)
	for i := 0; i < 9; i++ {
		d0 := c.x87IR("urem i64 %s, 10", cur)
		cur = c.x87IR("udiv i64 %s, 10", cur)
		d1 := c.x87IR("urem i64 %s, 10", cur)
		cur = c.x87IR("udiv i64 %s, 10", cur)
		pack := c.x87IR("trunc i64 %s to i8", c.x87IR("or i64 %s, %s", c.x87IR("shl i64 %s, 4", d1), d0))
		pb := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, i)
		fmt.Fprintf(c.b, "  store i8 %s, ptr %s, align 1\n", pack, pb)
	}
	p9 := c.x87IR("getelementptr i8, %s %s, i64 9", pty, p)
	sb := c.x87IR("select i1 %s, i8 -128, i8 0", neg)
	fmt.Fprintf(c.b, "  store i8 %s, ptr %s, align 1\n", sb, p9)
	c.popX87Value()
	return nil
}
