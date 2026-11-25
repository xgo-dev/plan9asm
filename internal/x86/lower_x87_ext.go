package x86

import (
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type x87ArithSpec struct {
	llvmOp  string // fadd, fsub, fmul, fdiv
	rev     bool   // reverse operand order (FSUBR / FDIVR)
	pop     bool   // pop stack after store
	memKind string // f64, f32, i32, i16
}

var x87ArithSpecs = map[asm.Op]x87ArithSpec{
	"FADDD":   {llvmOp: "fadd", memKind: "f64"},
	"FADDF":   {llvmOp: "fadd", memKind: "f32"},
	"FADDL":   {llvmOp: "fadd", memKind: "i32"},
	"FADDW":   {llvmOp: "fadd", memKind: "i16"},
	"FSUBD":   {llvmOp: "fsub", memKind: "f64"},
	"FSUBDP":  {llvmOp: "fsub", pop: true, memKind: "f64"},
	"FSUBF":   {llvmOp: "fsub", memKind: "f32"},
	"FSUBL":   {llvmOp: "fsub", memKind: "i32"},
	"FSUBW":   {llvmOp: "fsub", memKind: "i16"},
	"FSUBRD":  {llvmOp: "fsub", rev: true, memKind: "f64"},
	"FSUBRDP": {llvmOp: "fsub", rev: true, pop: true, memKind: "f64"},
	"FSUBRF":  {llvmOp: "fsub", rev: true, memKind: "f32"},
	"FSUBRL":  {llvmOp: "fsub", rev: true, memKind: "i32"},
	"FSUBRW":  {llvmOp: "fsub", rev: true, memKind: "i16"},
	"FMULF":   {llvmOp: "fmul", memKind: "f32"},
	"FMULL":   {llvmOp: "fmul", memKind: "i32"},
	"FMULW":   {llvmOp: "fmul", memKind: "i16"},
	"FDIVDP":  {llvmOp: "fdiv", pop: true, memKind: "f64"},
	"FDIVF":   {llvmOp: "fdiv", memKind: "f32"},
	"FDIVL":   {llvmOp: "fdiv", memKind: "i32"},
	"FDIVW":   {llvmOp: "fdiv", memKind: "i16"},
	"FDIVRD":  {llvmOp: "fdiv", rev: true, memKind: "f64"},
	"FDIVRDP": {llvmOp: "fdiv", rev: true, pop: true, memKind: "f64"},
	"FDIVRF":  {llvmOp: "fdiv", rev: true, memKind: "f32"},
	"FDIVRL":  {llvmOp: "fdiv", rev: true, memKind: "i32"},
	"FDIVRW":  {llvmOp: "fdiv", rev: true, memKind: "i16"},
}

type x87CmpSpec struct {
	memKind string // f64, f32, i32, i16
	pops    int
	eflags  bool
}

var x87CmpSpecs = map[asm.Op]x87CmpSpec{
	"FCOMD":   {memKind: "f64", pops: 0},
	"FCOMDP":  {memKind: "f64", pops: 1},
	"FCOMDPP": {memKind: "f64", pops: 2},
	"FCOMF":   {memKind: "f32", pops: 0},
	"FCOMFP":  {memKind: "f32", pops: 1},
	"FCOML":   {memKind: "i32", pops: 0},
	"FCOMLP":  {memKind: "i32", pops: 1},
	"FCOMW":   {memKind: "i16", pops: 0},
	"FCOMWP":  {memKind: "i16", pops: 1},
	"FCOMI":   {memKind: "f64", pops: 0, eflags: true},
	"FCOMIP":  {memKind: "f64", pops: 1, eflags: true},
	"FUCOM":   {memKind: "f64", pops: 0},
	"FUCOMP":  {memKind: "f64", pops: 1},
	"FUCOMPP": {memKind: "f64", pops: 2},
	"FUCOMIP": {memKind: "f64", pops: 1, eflags: true},
}

// Exact IEEE-754 80-bit extended (significand u64 as signed int64, sign+exp u16) constants.
var x87ConstSpecs = map[asm.Op][2]string{
	"FLDPI":  {"-3958705157555305931", "16384"}, // 0xc90fdaa22168c235, 0x4000
	"FLDL2E": {"-5140232325107978052", "16383"}, // 0xb8aa3b295c17f0bc, 0x3fff
	"FLDL2T": {"-3127057795212604674", "16384"}, // 0xd49a784bcd1b8afe, 0x4000
	"FLDLG2": {"-7340702247380289639", "16381"}, // 0x9a209a84fbcff799, 0x3ffd
	"FLDLN2": {"-5660434008982079060", "16382"}, // 0xb17217f7d1cf79ac, 0x3ffe
}

func isX87FCMOVOp(op asm.Op) bool {
	switch op {
	case "FCMOVB", "FCMOVBE", "FCMOVCC", "FCMOVCS", "FCMOVE", "FCMOVEQ",
		"FCMOVHI", "FCMOVLS", "FCMOVNB", "FCMOVNBE", "FCMOVNE", "FCMOVNU",
		"FCMOVU", "FCMOVUN":
		return true
	}
	return false
}

func isX87ExtOp(op asm.Op) bool {
	if _, ok := x87ArithSpecs[op]; ok {
		return true
	}
	if _, ok := x87CmpSpecs[op]; ok {
		return true
	}
	if _, ok := x87ConstSpecs[op]; ok {
		return true
	}
	if isX87FCMOVOp(op) {
		return true
	}
	switch op {
	case "FMOVF", "FMOVFP", "FMOVL", "FMOVLP", "FMOVW", "FMOVWP",
		"FMOVB", "FMOVBP", "FMOVX", "FMOVXP", "FBLD", "FBSTP",
		"FFREE", "FDECSTP", "FINCSTP", "FXAM",
		"FLDENV", "FSTENV", "FSAVE", "FRSTOR",
		"F2XM1", "FYL2X", "FYL2XP1", "FSIN", "FCOS", "FSINCOS",
		"FPTAN", "FPATAN", "FPREM", "FPREM1", "FSCALE", "FXTRACT":
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
		return true, false, c.pushX87Value(c.packX87(cst[0], cst[1]))
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
		return true, false, c.lowerX87ExtMovInt(8, op == "FMOVBP", ins)
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
		return true, false, nil
	case "FXAM":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FXAM takes no operands: %q", ins.Raw)
		}
		sig, se := c.partsX87(c.loadX87Value(0))
		neg := c.x87IR("icmp slt i16 %s, 0", se)
		exp := c.x87IR("and i16 %s, 32767", se)
		isZero := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 0", exp), c.x87IR("icmp eq i64 %s, 0", sig))
		isMax := c.x87IR("icmp eq i16 %s, 32767", exp)
		isInf := c.x87IR("and i1 %s, %s", isMax, c.x87IR("icmp eq i64 %s, -9223372036854775808", sig))
		isNaN := c.x87IR("and i1 %s, %s", isMax, c.x87IR("xor i1 %s, true", isInf))
		// Normal: C2=1 (0x0400); Zero: C3=1 (0x4000); Inf: C2|C0 (0x0500); NaN: C0 (0x0100); Sign: C1 (0x0200).
		st := c.x87IR("select i1 %s, i16 16384, i16 1024", isZero)
		st = c.x87IR("select i1 %s, i16 1280, i16 %s", isInf, st)
		st = c.x87IR("select i1 %s, i16 256, i16 %s", isNaN, st)
		c1 := c.x87IR("select i1 %s, i16 512, i16 0", neg)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", c.x87IR("or i16 %s, %s", st, c1), c.x87StatusSlot)
		return true, false, nil
	case "FLDENV", "FSTENV", "FSAVE", "FRSTOR":
		return true, false, c.lowerX87ExtEnv(op, ins)
	case "F2XM1", "FYL2X", "FYL2XP1", "FSIN", "FCOS", "FSINCOS",
		"FPTAN", "FPATAN", "FPREM", "FPREM1", "FSCALE", "FXTRACT":
		return true, false, c.lowerX87ExtMath(op, ins)
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

func (c *amd64Ctx) evalX87TypedF64(op asm.Operand, memKind string) (string, error) {
	if _, ok := x87OperandReg(op); ok {
		return c.evalX87F64(op)
	}
	switch memKind {
	case "f64":
		return c.evalF64(op)
	case "f32":
		f32, err := c.evalF32(op)
		if err != nil {
			return "", err
		}
		return c.x87IR("fpext float %s to double", f32), nil
	case "i32":
		iv, err := c.evalIntSized(op, asm.I32)
		if err != nil {
			return "", err
		}
		return c.x87IR("sitofp i32 %s to double", iv), nil
	default: // i16
		iv, err := c.evalIntSized(op, asm.I16)
		if err != nil {
			return "", err
		}
		return c.x87IR("sitofp i16 %s to double", iv), nil
	}
}

func (c *amd64Ctx) evalX87TypedValue(op asm.Operand, memKind string) (x87Value, error) {
	if idx, ok := x87OperandReg(op); ok {
		return c.loadX87Value(idx), nil
	}
	f64, err := c.evalX87TypedF64(op, memKind)
	if err != nil {
		return "", err
	}
	return c.f64ToX87Value(f64)
}

func (c *amd64Ctx) lowerX87ExtArith(op asm.Op, spec x87ArithSpec, ins asm.Instr) error {
	if len(ins.Args) != 2 {
		return fmt.Errorf("386 %s expects src, dst: %q", op, ins.Raw)
	}
	src, err := c.evalX87TypedF64(ins.Args[0], spec.memKind)
	if err != nil {
		return err
	}
	dst, err := c.evalX87F64(ins.Args[1])
	if err != nil {
		return err
	}
	lhs, rhs := dst, src
	if spec.rev {
		lhs, rhs = src, dst
	}
	out := c.x87IR("%s double %s, %s", spec.llvmOp, lhs, rhs)
	if err := c.storeX87F64(ins.Args[1], out); err != nil {
		return err
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
	eq, lt, uno := c.x87PortableCompare(lhs, rhs)
	if spec.eflags {
		z := c.x87IR("or i1 %s, %s", eq, uno)
		cf := c.x87IR("or i1 %s, %s", lt, uno)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	} else {
		c3 := c.x87IR("or i1 %s, %s", eq, uno)
		c0 := c.x87IR("or i1 %s, %s", lt, uno)
		c3w := c.x87IR("select i1 %s, i16 16384, i16 0", c3)
		c2w := c.x87IR("select i1 %s, i16 1024, i16 0", uno)
		c0w := c.x87IR("select i1 %s, i16 256, i16 0", c0)
		status := c.x87IR("or i16 %s, %s", c.x87IR("or i16 %s, %s", c3w, c2w), c0w)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", status, c.x87StatusSlot)
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
		cond = c.x87IR("and i1 %s, %s", cf, zf)
	default: // FCMOVNU
		cond = c.x87IR("xor i1 %s, true", c.x87IR("and i1 %s, %s", cf, zf))
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
	if dstIdx == 0 {
		return c.pushX87Value(v)
	}
	c.storeX87Value(dstIdx, v)
	return nil
}

func (c *amd64Ctx) lowerX87ExtBCD(store bool, ins asm.Instr) error {
	if len(ins.Args) != 1 {
		return fmt.Errorf("386 %s expects mem operand: %q", ins.Op, ins.Raw)
	}
	p, pty, err := c.x87MemPtr(ins.Args[0])
	if err != nil {
		return err
	}
	if !store {
		// FBLD: decode 18 packed BCD digits (bytes 0..8) + sign bit (byte 9 bit 7).
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
		return c.pushX87Value(x87v)
	}
	// FBSTP: encode signed i64 into 10-byte packed BCD and pop.
	iv, err := c.x87PortableToSigned(c.loadX87Value(0), 64, c.loadX87ControlWord())
	if err != nil {
		return err
	}
	neg := c.x87IR("icmp slt i64 %s, 0", iv)
	cur := c.x87IR("select i1 %s, i64 %s, i64 %s", neg, c.x87IR("sub i64 0, %s", iv), iv)
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

func (c *amd64Ctx) lowerX87ExtEnv(op asm.Op, ins asm.Instr) error {
	if len(ins.Args) != 1 {
		return fmt.Errorf("386 %s expects mem operand: %q", op, ins.Raw)
	}
	p, pty, err := c.x87MemPtr(ins.Args[0])
	if err != nil {
		return err
	}
	p4 := c.x87IR("getelementptr i8, %s %s, i64 4", pty, p)
	switch op {
	case "FLDENV", "FRSTOR":
		cw := c.x87IR("load i16, %s %s, align 1", pty, p)
		sw := c.x87IR("load i16, ptr %s, align 1", p4)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", cw, c.x87ControlSlot)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", sw, c.x87StatusSlot)
		c.x87CWInitialized = true
		if op == "FRSTOR" {
			for i := 0; i < 8; i++ {
				off := 28 + i*10
				ps := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, off)
				pe := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, off+8)
				sig := c.x87IR("load i64, ptr %s, align 1", ps)
				se := c.x87IR("load i16, ptr %s, align 1", pe)
				c.storeX87Value(i, c.packX87(sig, se))
			}
		}
	case "FSTENV", "FSAVE":
		cw := c.loadX87ControlWord()
		sw := c.x87IR("load i16, ptr %s", c.x87StatusSlot)
		fmt.Fprintf(c.b, "  store i16 %s, %s %s, align 1\n", cw, pty, p)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", sw, p4)
		if op == "FSAVE" {
			for i := 0; i < 8; i++ {
				off := 28 + i*10
				sig, se := c.partsX87(c.loadX87Value(i))
				ps := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, off)
				pe := c.x87IR("getelementptr i8, %s %s, i64 %d", pty, p, off+8)
				fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", sig, ps)
				fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", se, pe)
			}
		}
	}
	return nil
}

func (c *amd64Ctx) lowerX87ExtMath(op asm.Op, ins asm.Instr) error {
	if len(ins.Args) != 0 {
		return fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
	}
	if op == "FXTRACT" {
		sig, se := c.partsX87(c.loadX87Value(0))
		exp := c.x87IR("zext i16 %s to i64", c.x87IR("and i16 %s, 32767", se))
		unbiased := c.x87IR("sub i64 %s, 16383", exp)
		expX87, err := c.i64ToX87Value(unbiased)
		if err != nil {
			return err
		}
		sign := c.x87IR("and i16 %s, 32768", se)
		manX87 := c.packX87(sig, c.x87IR("or i16 %s, 16383", sign))
		c.storeX87Value(0, expX87)
		return c.pushX87Value(manX87)
	}
	st0, err := c.x87ValueToF64(c.loadX87Value(0))
	if err != nil {
		return err
	}
	storeF64 := func(idx int, v string) error {
		xv, err := c.f64ToX87Value(v)
		if err != nil {
			return err
		}
		c.storeX87Value(idx, xv)
		return nil
	}
	switch op {
	case "F2XM1":
		e2 := c.x87IR("call double @llvm.exp2.f64(double %s)", st0)
		return storeF64(0, c.x87IR("fsub double %s, 1.0", e2))
	case "FSIN":
		return storeF64(0, c.x87IR("call double @llvm.sin.f64(double %s)", st0))
	case "FCOS":
		return storeF64(0, c.x87IR("call double @llvm.cos.f64(double %s)", st0))
	case "FSINCOS":
		sv := c.x87IR("call double @llvm.sin.f64(double %s)", st0)
		cv := c.x87IR("call double @llvm.cos.f64(double %s)", st0)
		if err := storeF64(0, sv); err != nil {
			return err
		}
		cx, err := c.f64ToX87Value(cv)
		if err != nil {
			return err
		}
		return c.pushX87Value(cx)
	case "FPTAN":
		sv := c.x87IR("call double @llvm.sin.f64(double %s)", st0)
		cv := c.x87IR("call double @llvm.cos.f64(double %s)", st0)
		if err := storeF64(0, c.x87IR("fdiv double %s, %s", sv, cv)); err != nil {
			return err
		}
		return c.pushX87Value(c.packX87("-9223372036854775808", "16383"))
	case "FYL2X", "FYL2XP1":
		st1, err := c.x87ValueToF64(c.loadX87Value(1))
		if err != nil {
			return err
		}
		arg := st0
		if op == "FYL2XP1" {
			arg = c.x87IR("fadd double %s, 1.0", st0)
		}
		lg := c.x87IR("call double @llvm.log2.f64(double %s)", arg)
		if err := storeF64(1, c.x87IR("fmul double %s, %s", st1, lg)); err != nil {
			return err
		}
		c.popX87Value()
		return nil
	case "FPATAN":
		// Target-independent atan2(y=st1, x=st0) rational approximation in pure LLVM FP IR.
		st1, err := c.x87ValueToF64(c.loadX87Value(1))
		if err != nil {
			return err
		}
		ax := c.x87IR("call double @llvm.fabs.f64(double %s)", st0)
		ay := c.x87IR("call double @llvm.fabs.f64(double %s)", st1)
		swap := c.x87IR("fcmp ogt double %s, %s", ay, ax)
		num := c.x87IR("select i1 %s, double %s, double %s", swap, ax, ay)
		den := c.x87IR("select i1 %s, double %s, double %s", swap, ay, ax)
		denSafe := c.x87IR("select i1 %s, double 1.0, double %s", c.x87IR("fcmp oeq double %s, 0.0", den), den)
		z := c.x87IR("fdiv double %s, %s", num, denSafe)
		z2 := c.x87IR("fmul double %s, %s", z, z)
		// z / (1 + 0.28125 * z^2) accurately approximates atan(z) on [0, 1] without libm.
		poly := c.x87IR("fdiv double %s, %s", z, c.x87IR("fadd double 1.0, %s", c.x87IR("fmul double 0x3FD2000000000000, %s", z2)))
		halfPi := "0x3FF921FB54442D18"
		pi := "0x400921FB54442D18"
		ang := c.x87IR("select i1 %s, double %s, double %s", swap, c.x87IR("fsub double %s, %s", halfPi, poly), poly)
		xNeg := c.x87IR("fcmp olt double %s, 0.0", st0)
		ang = c.x87IR("select i1 %s, double %s, double %s", xNeg, c.x87IR("fsub double %s, %s", pi, ang), ang)
		yNeg := c.x87IR("fcmp olt double %s, 0.0", st1)
		ang = c.x87IR("select i1 %s, double %s, double %s", yNeg, c.x87IR("fneg double %s", ang), ang)
		if err := storeF64(1, ang); err != nil {
			return err
		}
		c.popX87Value()
		return nil
	case "FPREM", "FPREM1":
		st1, err := c.x87ValueToF64(c.loadX87Value(1))
		if err != nil {
			return err
		}
		if op == "FPREM" {
			return storeF64(0, c.x87IR("frem double %s, %s", st0, st1))
		}
		q := c.x87IR("call double @llvm.roundeven.f64(double %s)", c.x87IR("fdiv double %s, %s", st0, st1))
		return storeF64(0, c.x87IR("fsub double %s, %s", st0, c.x87IR("fmul double %s, %s", q, st1)))
	default: // FSCALE
		st1, err := c.x87ValueToF64(c.loadX87Value(1))
		if err != nil {
			return err
		}
		tr := c.x87IR("call double @llvm.trunc.f64(double %s)", st1)
		sc := c.x87IR("call double @llvm.exp2.f64(double %s)", tr)
		return storeF64(0, c.x87IR("fmul double %s, %s", st0, sc))
	}
}
