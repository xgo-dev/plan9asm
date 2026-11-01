package plan9asm

import (
	"fmt"
	"strings"
)

func isX87Op(op Op) bool {
	switch op {
	case "FMOVB", "FMOVBP", "FMOVD", "FMOVDP", "FMOVF", "FMOVFP",
		"FMOVL", "FMOVLP", "FMOVV", "FMOVVP", "FMOVW", "FMOVWP",
		"FMOVX", "FMOVXP", "FBLD", "FBSTP", "FXCHD",
		"FADDW", "FADDL", "FADDF", "FADDD", "FADDDP",
		"FMULW", "FMULL", "FMULF", "FMULD", "FMULDP",
		"FSUBW", "FSUBL", "FSUBF", "FSUBD", "FSUBDP",
		"FSUBRW", "FSUBRL", "FSUBRF", "FSUBRD", "FSUBRDP",
		"FDIVW", "FDIVL", "FDIVF", "FDIVD", "FDIVDP",
		"FDIVRW", "FDIVRL", "FDIVRF", "FDIVRD", "FDIVRDP",
		"FCOMD", "FCOMDP", "FCOMDPP", "FCOMF", "FCOMFP", "FCOMI", "FCOMIP",
		"FCOML", "FCOMLP", "FCOMW", "FCOMWP",
		"FUCOM", "FUCOMI", "FUCOMIP", "FUCOMP", "FUCOMPP",
		"FCMOVCC", "FCMOVCS", "FCMOVEQ", "FCMOVHI", "FCMOVLS",
		"FCMOVB", "FCMOVBE", "FCMOVNB", "FCMOVNBE", "FCMOVE", "FCMOVNE", "FCMOVNU", "FCMOVU", "FCMOVUN",
		"FSTCW", "FLDCW", "FLDENV", "FRSTOR", "FSAVE", "FSTENV", "FRNDINT",
		"F2XM1", "FABS", "FCHS", "FCLEX", "FCOS", "FDECSTP", "FINCSTP", "FINIT",
		"FTST", "FSTSW", "FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2",
		"FLDPI", "FLDZ", "FNOP", "FPATAN", "FPREM", "FPREM1", "FPTAN", "FSCALE",
		"FSIN", "FSINCOS", "FSQRT", "FXAM", "FXTRACT", "FYL2X", "FYL2XP1":
		return true
	default:
		return false
	}
}

func (c *amd64Ctx) lowerX87(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if !isX87Op(op) {
		return false, false, nil
	}
	dispatch := ins
	if dispatch.Op == "" {
		dispatch.Op = op // Legacy direct-helper callers have no second source head.
	} else if !strings.EqualFold(string(dispatch.Op), string(op)) {
		return true, false, fmt.Errorf("%s x87 dispatch/source opcode differs: %q", c.goarch, ins.Raw)
	}
	arch := c.goarch
	if arch == "" {
		arch = "amd64" // Legacy private helpers have always used the default x86 mode.
	}
	if _, known, err := x86X87WordProperties(dispatch, arch); known && err != nil {
		return true, false, err
	}
	if _, known, err := x86X87EnvironmentReadProperties(dispatch, arch); known && err != nil {
		return true, false, err
	}
	valueForm, typedValue, formErr := x86X87ValueProperties(dispatch, arch)
	if typedValue && formErr != nil {
		return true, false, formErr
	}
	if typedValue && valueForm.spec.kind == x86X87IntegerMove {
		return true, false, c.lowerX87IntegerMove(valueForm)
	}
	switch op {
	case "FBLD":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FBLD expects memory source: %q", ins.Raw)
		}
		value, err := c.loadX87PackedBCD(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		return true, false, c.pushX87(value)

	case "FBSTP":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FBSTP expects memory destination: %q", ins.Raw)
		}
		if err := c.storeX87PackedBCD(ins.Args[0], c.loadX87(0)); err != nil {
			return true, false, err
		}
		c.popX87()
		return true, false, nil

	case "FMOVB", "FMOVX":
		if len(ins.Args) != 2 || !isX87MemoryOperand(ins.Args[0]) || !isX87F0(ins.Args[1]) {
			return true, false, fmt.Errorf("386 %s expects memory source and F0 destination: %q", op, ins.Raw)
		}
		var value string
		var err error
		if op == "FMOVB" {
			value, err = c.loadX87PackedBCD(ins.Args[0])
		} else {
			value, err = c.loadX87Extended(ins.Args[0])
		}
		if err != nil {
			return true, false, err
		}
		return true, false, c.pushX87(value)

	case "FMOVBP", "FMOVXP":
		if len(ins.Args) != 2 || !isX87F0(ins.Args[0]) || !isX87MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("386 %s expects F0 source and memory destination: %q", op, ins.Raw)
		}
		var err error
		if op == "FMOVBP" {
			err = c.storeX87PackedBCD(ins.Args[1], c.loadX87(0))
		} else {
			err = c.storeX87Extended(ins.Args[1], c.loadX87(0))
		}
		if err != nil {
			return true, false, err
		}
		c.popX87()
		return true, false, nil

	case "FMOVD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVD expects src, dst: %q", ins.Raw)
		}
		srcReg, srcIsReg := x87OperandReg(ins.Args[0])
		dstReg, dstIsReg := x87OperandReg(ins.Args[1])
		valid := (isX87MemoryOperand(ins.Args[0]) || ins.Args[0].Kind == OpImm) && dstIsReg && dstReg == 0 ||
			srcIsReg && srcReg == 0 && (isX87MemoryOperand(ins.Args[1]) || dstIsReg) ||
			srcIsReg && dstIsReg && dstReg == 0
		if !valid {
			return true, false, fmt.Errorf("386 FMOVD expects memory,F0, Freg,F0, F0,memory, or F0,Freg: %q", ins.Raw)
		}
		if srcIsReg {
			value := c.loadX87IntegerValue(srcReg)
			if valueForm.push {
				return true, false, c.pushX87IntegerValue(value)
			}
			if dstIsReg {
				c.storeX87IntegerValue(dstReg, value)
				return true, false, nil
			}
		}
		v, err := c.loadX87FloatingMove(ins.Args[0], 64)
		if err != nil {
			return true, false, err
		}
		if valueForm.push {
			return true, false, c.pushX87(v)
		}
		return true, false, c.storeX87F64(ins.Args[1], v)

	case "FMOVDP":
		if len(ins.Args) != 2 || !isX87F0(ins.Args[0]) || !(isX87MemoryOperand(ins.Args[1]) || isX87RegisterOperand(ins.Args[1])) {
			return true, false, fmt.Errorf("386 FMOVDP expects F0 source and memory or x87-register destination: %q", ins.Raw)
		}
		if index, register := x87OperandReg(ins.Args[1]); register {
			value := c.loadX87IntegerValue(0)
			c.storeX87IntegerValue(index, value)
			c.popX87()
			return true, false, nil
		}
		v, err := c.evalX87F64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if err := c.storeX87F64(ins.Args[1], v); err != nil {
			return true, false, err
		}
		c.popX87()
		return true, false, nil

	case "FMOVF":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 %s expects src, dst: %q", op, ins.Raw)
		}
		if (isX87MemoryOperand(ins.Args[0]) || op == "FMOVF" && valueForm.push) && isX87F0(ins.Args[1]) {
			value, err := c.loadX87MoveValue(op, ins.Args[0])
			if err != nil {
				return true, false, err
			}
			return true, false, c.pushX87(value)
		}
		if isX87F0(ins.Args[0]) && isX87MemoryOperand(ins.Args[1]) {
			return true, false, c.storeX87MoveValue(op, ins.Args[1], c.loadX87(0))
		}
		return true, false, fmt.Errorf("386 %s expects memory source and F0 destination, or F0 source and memory destination: %q", op, ins.Raw)

	case "FMOVFP":
		if len(ins.Args) != 2 || !isX87F0(ins.Args[0]) || !isX87MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("386 %s expects F0 source and memory destination: %q", op, ins.Raw)
		}
		baseOp := Op(strings.TrimSuffix(string(op), "P"))
		if err := c.storeX87MoveValue(baseOp, ins.Args[1], c.loadX87(0)); err != nil {
			return true, false, err
		}
		c.popX87()
		return true, false, nil

	case "FXCHD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FXCHD expects Fsrc, Fdst: %q", ins.Raw)
		}
		a, okA := x87OperandReg(ins.Args[0])
		bv, okB := x87OperandReg(ins.Args[1])
		if !okA || !okB {
			return true, false, fmt.Errorf("386 FXCHD expects x87 registers: %q", ins.Raw)
		}
		av := c.loadX87IntegerValue(a)
		b := c.loadX87IntegerValue(bv)
		c.storeX87IntegerValue(a, b)
		c.storeX87IntegerValue(bv, av)
		return true, false, nil

	case "FADDW", "FADDL", "FADDF", "FADDD", "FADDDP",
		"FMULW", "FMULL", "FMULF", "FMULD", "FMULDP",
		"FSUBW", "FSUBL", "FSUBF", "FSUBD", "FSUBDP",
		"FSUBRW", "FSUBRL", "FSUBRF", "FSUBRD", "FSUBRDP",
		"FDIVW", "FDIVL", "FDIVF", "FDIVD", "FDIVDP",
		"FDIVRW", "FDIVRL", "FDIVRF", "FDIVRD", "FDIVRDP":
		return true, false, c.lowerX87Arithmetic(op, ins, valueForm)

	case "FCOMD", "FCOMDP", "FCOMDPP", "FCOMF", "FCOMFP", "FCOMI", "FCOMIP",
		"FCOML", "FCOMLP", "FCOMW", "FCOMWP",
		"FUCOM", "FUCOMI", "FUCOMIP", "FUCOMP", "FUCOMPP":
		return true, false, c.lowerX87Compare(op, ins, valueForm)

	case "FCMOVCC", "FCMOVCS", "FCMOVEQ", "FCMOVHI", "FCMOVLS",
		"FCMOVB", "FCMOVBE", "FCMOVNB", "FCMOVNBE", "FCMOVE", "FCMOVNE", "FCMOVNU", "FCMOVU", "FCMOVUN":
		return true, false, c.lowerX87ConditionalMove(op, ins)

	case "FSTCW":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FSTCW expects memory destination: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			c.storeHardwareX87ControlWord()
		}
		cw := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", cw, c.x87ControlSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+cw)

	case "FLDCW":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 FLDCW expects memory source: %q", ins.Raw)
		}
		cw, err := c.evalIntSized(ins.Args[0], I16)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", cw, c.x87ControlSlot)
		if c.useHardwareX87() {
			c.loadHardwareX87ControlWord()
		}
		return true, false, nil

	case "FLDENV", "FRSTOR":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 %s expects memory source: %q", op, ins.Raw)
		}
		return true, false, c.loadX87Environment(ins.Args[0])

	case "FSAVE", "FSTENV":
		if len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("386 %s expects memory destination: %q", op, ins.Raw)
		}
		if err := c.storeX87Environment(ins.Args[0]); err != nil {
			return true, false, err
		}
		if op == "FSAVE" {
			for i := range c.x87Slot {
				c.storeX87(i, "0.000000e+00")
			}
			fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot)
			fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		}
		return true, false, nil

	case "FRNDINT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FRNDINT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			c.roundX87Hardware(c.x87Slot[0])
			return true, false, nil
		}
		value := c.loadX87IntegerValue(0)
		value.floating = c.roundX87Software(value.floating)
		c.storeX87IntegerValue(0, value)
		return true, false, nil

	case "F2XM1":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 F2XM1 takes no operands: %q", ins.Raw)
		}
		value := c.loadX87(0)
		power := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.exp2.f64(double %s)\n", power, value)
		fmt.Fprintf(c.b, "  %%%s = fsub double %%%s, 1.000000e+00\n", result, power)
		c.storeX87(0, "%"+result)
		return true, false, nil

	case "FABS", "FSQRT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		v := c.loadX87(0)
		out := c.newTmp()
		intrinsic := "llvm.fabs.f64"
		if op == "FSQRT" {
			intrinsic = "llvm.sqrt.f64"
		}
		fmt.Fprintf(c.b, "  %%%s = call double @%s(double %s)\n", out, intrinsic, v)
		c.storeX87(0, "%"+out)
		return true, false, nil

	case "FCHS":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FCHS takes no operands: %q", ins.Raw)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg double %s\n", result, c.loadX87(0))
		c.storeX87(0, "%"+result)
		return true, false, nil

	case "FCLEX":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FCLEX takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fnclex", "~{fpsr}"()`)
		}
		status := c.newTmp()
		conditionCodes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, 32512\n", conditionCodes, status) // Preserve TOP and C3,C2,C1,C0.
		fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", conditionCodes, c.x87StatusSlot)
		return true, false, nil

	case "FCOS", "FSIN":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		intrinsic := "llvm.cos.f64"
		if op == "FSIN" {
			intrinsic = "llvm.sin.f64"
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @%s(double %s)\n", result, intrinsic, c.loadX87(0))
		c.storeX87(0, "%"+result)
		c.clearX87C2()
		return true, false, nil

	case "FDECSTP", "FINCSTP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		c.rotateX87Stack(op == "FINCSTP")
		return true, false, nil

	case "FINIT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FINIT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fninit", "~{st},~{st(1)},~{st(2)},~{st(3)},~{st(4)},~{st(5)},~{st(6)},~{st(7)},~{fpsr}"()`)
		}
		for i := range c.x87Slot {
			c.storeX87(i, "0.000000e+00")
		}
		fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot)
		fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		return true, false, nil

	case "FNOP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FNOP takes no operands: %q", ins.Raw)
		}
		return true, false, nil

	case "FPATAN":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FPATAN takes no operands: %q", ins.Raw)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @atan2(double %s, double %s)\n", result, c.loadX87(1), c.loadX87(0))
		c.storeX87(1, "%"+result)
		c.popX87()
		return true, false, nil

	case "FPREM", "FPREM1":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		function := "fmod"
		if op == "FPREM1" {
			function = "remainder"
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @%s(double %s, double %s)\n", result, function, c.loadX87(0), c.loadX87(1))
		c.storeX87(0, "%"+result)
		c.clearX87C2()
		return true, false, nil

	case "FPTAN":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FPTAN takes no operands: %q", ins.Raw)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @tan(double %s)\n", result, c.loadX87(0))
		c.storeX87(0, "%"+result)
		if err := c.pushX87("1.000000e+00"); err != nil {
			return true, false, err
		}
		c.clearX87C2()
		return true, false, nil

	case "FSCALE":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FSCALE takes no operands: %q", ins.Raw)
		}
		exponent := c.newTmp()
		scale := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.trunc.f64(double %s)\n", exponent, c.loadX87(1))
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.exp2.f64(double %%%s)\n", scale, exponent)
		fmt.Fprintf(c.b, "  %%%s = fmul double %s, %%%s\n", result, c.loadX87(0), scale)
		c.storeX87(0, "%"+result)
		return true, false, nil

	case "FSINCOS":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FSINCOS takes no operands: %q", ins.Raw)
		}
		value := c.loadX87(0)
		sine := c.newTmp()
		cosine := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.sin.f64(double %s)\n", sine, value)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.cos.f64(double %s)\n", cosine, value)
		c.storeX87(0, "%"+sine)
		if err := c.pushX87("%" + cosine); err != nil {
			return true, false, err
		}
		c.clearX87C2()
		return true, false, nil

	case "FXAM":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FXAM takes no operands: %q", ins.Raw)
		}
		c.classifyX87F0()
		return true, false, nil

	case "FXTRACT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FXTRACT takes no operands: %q", ins.Raw)
		}
		value := c.loadX87(0)
		abs := c.newTmp()
		log := c.newTmp()
		exponent := c.newTmp()
		scale := c.newTmp()
		significand := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %s)\n", abs, value)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.log2.f64(double %%%s)\n", log, abs)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.floor.f64(double %%%s)\n", exponent, log)
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.exp2.f64(double %%%s)\n", scale, exponent)
		fmt.Fprintf(c.b, "  %%%s = fdiv double %s, %%%s\n", significand, value, scale)
		c.storeX87(0, "%"+significand)
		return true, false, c.pushX87("%" + exponent)

	case "FYL2X", "FYL2XP1":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		x := c.loadX87(0)
		if op == "FYL2XP1" {
			incremented := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fadd double %s, 1.000000e+00\n", incremented, x)
			x = "%" + incremented
		}
		log := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.log2.f64(double %s)\n", log, x)
		fmt.Fprintf(c.b, "  %%%s = fmul double %s, %%%s\n", result, c.loadX87(1), log)
		c.storeX87(1, "%"+result)
		c.popX87()
		return true, false, nil

	case "FTST":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FTST takes no operands: %q", ins.Raw)
		}
		value := c.loadX87(0)
		equal := c.newTmp()
		less := c.newTmp()
		unordered := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %s, 0.000000e+00\n", equal, value)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt double %s, 0.000000e+00\n", less, value)
		fmt.Fprintf(c.b, "  %%%s = fcmp uno double %s, 0.000000e+00\n", unordered, value)
		c3 := c.newTmp()
		c0 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c3, equal, unordered)
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c0, less, unordered)
		c3word := c.newTmp()
		c2word := c.newTmp()
		c0word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 16384, i16 0\n", c3word, c3)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 1024, i16 0\n", c2word, unordered)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 256, i16 0\n", c0word, c0)
		status01 := c.newTmp()
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", status01, c3word, c2word)
		fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", status, status01, c0word)
		fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", status, c.x87StatusSlot)
		return true, false, nil

	case "FSTSW":
		if len(ins.Args) != 1 || !(isX87MemoryOperand(ins.Args[0]) || ins.Args[0].Kind == OpReg && ins.Args[0].Reg == AX) {
			return true, false, fmt.Errorf("386 FSTSW expects memory destination or AX: %q", ins.Raw)
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+status)

	case "FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FLDPI", "FLDZ":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		constant := map[Op]string{
			"FLD1":   "1.0000000000000000e+00",
			"FLDL2E": "1.4426950408889634e+00",
			"FLDL2T": "3.3219280948873623e+00",
			"FLDLG2": "3.0102999566398120e-01",
			"FLDLN2": "6.9314718055994531e-01",
			"FLDPI":  "3.1415926535897931e+00",
			"FLDZ":   "0.0000000000000000e+00",
		}
		return true, false, c.pushX87(constant[op])
	}
	return false, false, nil
}

func (c *amd64Ctx) lowerX87Arithmetic(op Op, ins Instr, form x86X87ValueForm) error {
	width := form.spec.width
	var src string
	var err error
	switch width {
	case 'W', 'L':
		typ := I16
		if width == 'L' {
			typ = I32
		}
		integer, evalErr := c.evalIntSized(ins.Args[0], typ)
		if evalErr != nil {
			return evalErr
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to double\n", converted, typ, integer)
		src = "%" + converted
	case 'F':
		value, evalErr := c.evalF32(ins.Args[0])
		if evalErr != nil {
			return evalErr
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", converted, value)
		src = "%" + converted
	case 'D':
		src, err = c.evalX87F64(ins.Args[0])
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("386 %s has unknown x87 arithmetic width", op)
	}
	dst, err := c.evalX87F64(ins.Args[1])
	if err != nil {
		return err
	}
	lhs, rhs := dst, src
	if form.spec.reverse {
		lhs, rhs = src, dst
	}
	operation := ""
	switch {
	case form.spec.stem == "FADD":
		operation = "fadd"
	case form.spec.stem == "FMUL":
		operation = "fmul"
	case form.spec.stem == "FSUB" || form.spec.stem == "FSUBR":
		operation = "fsub"
	case form.spec.stem == "FDIV" || form.spec.stem == "FDIVR":
		operation = "fdiv"
	}
	if operation == "" {
		return fmt.Errorf("386 %s has unknown x87 arithmetic operation", op)
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s double %s, %s\n", result, operation, lhs, rhs)
	if err := c.storeX87F64(ins.Args[1], "%"+result); err != nil {
		return err
	}
	if form.spec.pop != 0 {
		c.popX87()
	}
	return nil
}

func (c *amd64Ctx) lowerX87Compare(op Op, ins Instr, form x86X87ValueForm) error {
	lhs, err := c.evalX87F64(form.left)
	if err != nil {
		return err
	}
	var rhs string
	switch form.spec.width {
	case 'D':
		rhs, err = c.evalX87F64(form.right)
	case 'F':
		var narrow string
		narrow, err = c.evalF32(form.right)
		if err == nil {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", wide, narrow)
			rhs = "%" + wide
		}
	case 'L', 'W':
		typ := I16
		if form.spec.width == 'L' {
			typ = I32
		}
		var integer string
		integer, err = c.evalIntSized(form.right, typ)
		if err == nil {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to double\n", wide, typ, integer)
			rhs = "%" + wide
		}
	default:
		return fmt.Errorf("386 %s has unknown x87 compare width", op)
	}
	if err != nil {
		return err
	}
	if form.spec.directFlags {
		c.setX87CompareFlags(lhs, rhs)
	} else {
		c.setX87CompareStatus(lhs, rhs)
	}
	for i := uint8(0); i < form.spec.pop; i++ {
		c.popX87()
	}
	return nil
}

func (c *amd64Ctx) x87CompareBits(lhs, rhs string) (equal, less, unordered string) {
	equalTmp := c.newTmp()
	lessTmp := c.newTmp()
	unorderedTmp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp ueq double %s, %s\n", equalTmp, lhs, rhs)
	fmt.Fprintf(c.b, "  %%%s = fcmp ult double %s, %s\n", lessTmp, lhs, rhs)
	fmt.Fprintf(c.b, "  %%%s = fcmp uno double %s, %s\n", unorderedTmp, lhs, rhs)
	return equalTmp, lessTmp, unorderedTmp
}

func (c *amd64Ctx) setX87CompareFlags(lhs, rhs string) {
	equal, less, unordered := c.x87CompareBits(lhs, rhs)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", equal, c.flagsZSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", less, c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", unordered, c.flagsPFSlot)
	// FCOMI/FUCOMI clear OF, SF, and AF. flagsSltSlot is architectural SF.
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsAFSlot)
}

func (c *amd64Ctx) setX87CompareStatus(lhs, rhs string) {
	equal, less, unordered := c.x87CompareBits(lhs, rhs)
	c3Word := c.x87StatusBit(equal, 16384)
	c2Word := c.x87StatusBit(unordered, 1024)
	c0Word := c.x87StatusBit(less, 256)
	partial := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i16 %s, %s\n", partial, c3Word, c2Word)
	fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %s\n", status, partial, c0Word)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", status, c.x87StatusSlot)
}

func x87OperandReg(op Operand) (int, bool) {
	if op.Kind != OpReg {
		return 0, false
	}
	return amd64ParseX87Reg(op.Reg)
}

func isX87RegisterOperand(op Operand) bool {
	_, ok := x87OperandReg(op)
	return ok
}

func isX87F0(op Operand) bool {
	index, ok := x87OperandReg(op)
	return ok && index == 0
}

func isX87MemoryOperand(op Operand) bool {
	return isAMD64MemoryOperand(op)
}

func (c *amd64Ctx) loadX87MoveValue(op Op, src Operand) (string, error) {
	switch op {
	case "FMOVF":
		value, err := c.loadX87FloatingMove(src, 32)
		if err != nil {
			return "", err
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fpext float %s to double\n", wide, value)
		return "%" + wide, nil
	case "FMOVL", "FMOVW":
		typ := I32
		if op == "FMOVW" {
			typ = I16
		}
		value, err := c.evalIntSized(src, typ)
		if err != nil {
			return "", err
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to double\n", wide, typ, value)
		return "%" + wide, nil
	default:
		return "", fmt.Errorf("386: unsupported x87 move load %s", op)
	}
}

func (c *amd64Ctx) storeX87MoveValue(op Op, dst Operand, value string) error {
	switch op {
	case "FMOVF":
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fptrunc double %s to float\n", narrow, value)
		return c.storeX87TypedMemory(dst, LLVMType("float"), "%"+narrow)
	case "FMOVL", "FMOVW":
		bits := 32
		if op == "FMOVW" {
			bits = 16
		}
		rounded := c.roundX87Software(value)
		return c.storeX87TypedMemory(dst, amd64IntegerTypeForBits(bits), c.convertRoundedX87Integer(rounded, bits))
	default:
		return fmt.Errorf("386: unsupported x87 move store %s", op)
	}
}

func (c *amd64Ctx) storeX87TypedMemory(dst Operand, typ LLVMType, value string) error {
	if typ == LLVMType("float") || typ == LLVMType("double") {
		if handled, err := c.storeX87NativeFloatingMove(dst, typ, value); handled {
			return err
		}
	}
	if dst.Kind == OpFP {
		if typ == LLVMType("float") {
			return c.storeScalarFPFloat(dst.FPOffset, 32, value)
		}
		return c.storeFPResult(dst.FPOffset, typ, value)
	}
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, value, ptrType, ptr)
	return nil
}

func (c *amd64Ctx) x87MemoryPointer(op Operand) (string, string, error) {
	if !isX87MemoryOperand(op) {
		return "", "", fmt.Errorf("386 x87 instruction expected memory, got %s", op.String())
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(op)
	if err != nil {
		return "", "", fmt.Errorf("386 x87 memory operand %s: %w", op.String(), err)
	}
	return ptr, ptrType, nil
}

func (c *amd64Ctx) loadX87Environment(src Operand) error {
	ptr, ptrType, err := c.x87MemoryPointer(src)
	if err != nil {
		return err
	}
	// The 32-bit environment is one observable 28-byte read, including the
	// fields that this software model does not interpret. Keep it exact and
	// volatile even when both captured words are dead. An aggregate-width
	// integer load avoids 28 separate IR accesses and preserves address space.
	environment := c.newTmp()
	control := c.newTmp()
	statusBits := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load volatile i224, %s %s, align 1\n", environment, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = trunc i224 %%%s to i16\n", control, environment)
	fmt.Fprintf(c.b, "  %%%s = lshr i224 %%%s, 32\n", statusBits, environment)
	fmt.Fprintf(c.b, "  %%%s = trunc i224 %%%s to i16\n", status, statusBits)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", control, c.x87ControlSlot)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", status, c.x87StatusSlot)
	if c.useHardwareX87() {
		c.loadHardwareX87ControlWord()
	}
	return nil
}

func (c *amd64Ctx) storeX87Environment(dst Operand) error {
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	if c.useHardwareX87() {
		c.storeHardwareX87ControlWord()
	}
	control := c.newTmp()
	status := c.newTmp()
	statusPtr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", control, c.x87ControlSlot)
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
	fmt.Fprintf(c.b, "  store i16 %%%s, %s %s, align 1\n", control, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 4\n", statusPtr, ptrType, ptr)
	fmt.Fprintf(c.b, "  store i16 %%%s, %s %%%s, align 1\n", status, ptrType, statusPtr)
	return nil
}

func (c *amd64Ctx) loadX87Extended(src Operand) (string, error) {
	ptr, ptrType, err := c.x87MemoryPointer(src)
	if err != nil {
		return "", err
	}
	extended := c.newTmp()
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load x86_fp80, %s %s, align 1\n", extended, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = fptrunc x86_fp80 %%%s to double\n", value, extended)
	return "%" + value, nil
}

func (c *amd64Ctx) storeX87Extended(dst Operand, value string) error {
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	extended := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext double %s to x86_fp80\n", extended, value)
	fmt.Fprintf(c.b, "  store x86_fp80 %%%s, %s %s, align 1\n", extended, ptrType, ptr)
	return nil
}

func (c *amd64Ctx) loadX87PackedBCD(src Operand) (string, error) {
	ptr, ptrType, err := c.x87MemoryPointer(src)
	if err != nil {
		return "", err
	}
	accumulator := "0"
	for i := 8; i >= 0; i-- {
		bytePtr := c.newTmp()
		packed := c.newTmp()
		low := c.newTmp()
		highShifted := c.newTmp()
		high := c.newTmp()
		low64 := c.newTmp()
		high64 := c.newTmp()
		digit10 := c.newTmp()
		digits := c.newTmp()
		scaled := c.newTmp()
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %d\n", bytePtr, ptrType, ptr, i)
		fmt.Fprintf(c.b, "  %%%s = load i8, %s %%%s, align 1\n", packed, ptrType, bytePtr)
		fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n", low, packed)
		fmt.Fprintf(c.b, "  %%%s = lshr i8 %%%s, 4\n", highShifted, packed)
		fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, 15\n", high, highShifted)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", low64, low)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", high64, high)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, 10\n", digit10, high64)
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", digits, digit10, low64)
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, 100\n", scaled, accumulator)
		fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", next, scaled, digits)
		accumulator = "%" + next
	}
	signPtr := c.newTmp()
	signByte := c.newTmp()
	signBits := c.newTmp()
	isNegative := c.newTmp()
	negative := c.newTmp()
	signed := c.newTmp()
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 9\n", signPtr, ptrType, ptr)
	fmt.Fprintf(c.b, "  %%%s = load i8, %s %%%s, align 1\n", signByte, ptrType, signPtr)
	fmt.Fprintf(c.b, "  %%%s = and i8 %%%s, -128\n", signBits, signByte)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", isNegative, signBits)
	fmt.Fprintf(c.b, "  %%%s = sub i64 0, %s\n", negative, accumulator)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %s\n", signed, isNegative, negative, accumulator)
	fmt.Fprintf(c.b, "  %%%s = sitofp i64 %%%s to double\n", value, signed)
	return "%" + value, nil
}

func (c *amd64Ctx) storeX87PackedBCD(dst Operand, value string) error {
	ptr, ptrType, err := c.x87MemoryPointer(dst)
	if err != nil {
		return err
	}
	rounded := c.roundX87Software(value)
	integer := c.newTmp()
	isNegative := c.newTmp()
	negated := c.newTmp()
	absolute := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fptosi double %s to i64\n", integer, rounded)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, 0\n", isNegative, integer)
	fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", negated, integer)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", absolute, isNegative, negated, integer)
	remaining := "%" + absolute
	for i := 0; i < 9; i++ {
		digits := c.newTmp()
		tens := c.newTmp()
		ones := c.newTmp()
		tensByte := c.newTmp()
		onesByte := c.newTmp()
		shifted := c.newTmp()
		packed := c.newTmp()
		bytePtr := c.newTmp()
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = urem i64 %s, 100\n", digits, remaining)
		fmt.Fprintf(c.b, "  %%%s = udiv i64 %%%s, 10\n", tens, digits)
		fmt.Fprintf(c.b, "  %%%s = urem i64 %%%s, 10\n", ones, digits)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", tensByte, tens)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", onesByte, ones)
		fmt.Fprintf(c.b, "  %%%s = shl i8 %%%s, 4\n", shifted, tensByte)
		fmt.Fprintf(c.b, "  %%%s = or i8 %%%s, %%%s\n", packed, shifted, onesByte)
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %d\n", bytePtr, ptrType, ptr, i)
		fmt.Fprintf(c.b, "  store i8 %%%s, %s %%%s, align 1\n", packed, ptrType, bytePtr)
		fmt.Fprintf(c.b, "  %%%s = udiv i64 %s, 100\n", next, remaining)
		remaining = "%" + next
	}
	sign := c.newTmp()
	signPtr := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i8 -128, i8 0\n", sign, isNegative)
	fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 9\n", signPtr, ptrType, ptr)
	fmt.Fprintf(c.b, "  store i8 %%%s, %s %%%s, align 1\n", sign, ptrType, signPtr)
	return nil
}

func (c *amd64Ctx) loadX87(index int) string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load double, ptr %s\n", t, c.x87Slot[index])
	return "%" + t
}

func (c *amd64Ctx) storeX87(index int, value string) {
	fmt.Fprintf(c.b, "  store double %s, ptr %s\n", value, c.x87Slot[index])
	if c.x87ExactSlot[index] != "" {
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.x87ExactSlot[index])
	}
}

func (c *amd64Ctx) pushX87(value string) error {
	return c.pushX87IntegerValue(x87IntegerValue{value, "0", "false"})
}

func (c *amd64Ctx) popX87() {
	for i := 0; i < len(c.x87Slot)-1; i++ {
		c.storeX87IntegerValue(i, c.loadX87IntegerValue(i+1))
	}
	c.storeX87(len(c.x87Slot)-1, "0.000000e+00")
}

func (c *amd64Ctx) rotateX87Stack(increment bool) {
	values := make([]x87IntegerValue, len(c.x87Slot))
	for i := range values {
		values[i] = c.loadX87IntegerValue(i)
	}
	if increment {
		for i := range values {
			c.storeX87IntegerValue(i, values[(i+1)%len(values)])
		}
		return
	}
	for i := range values {
		c.storeX87IntegerValue(i, values[(i+len(values)-1)%len(values)])
	}
}

func (c *amd64Ctx) clearX87C2() {
	status := c.newTmp()
	cleared := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
	fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, -1025\n", cleared, status)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", cleared, c.x87StatusSlot)
}

func (c *amd64Ctx) classifyX87F0() {
	value := c.loadX87(0)
	isNaN := c.newTmp()
	isZero := c.newTmp()
	abs := c.newTmp()
	isInfinity := c.newTmp()
	notNaN := c.newTmp()
	notZero := c.newTmp()
	c2 := c.newTmp()
	c0 := c.newTmp()
	bits := c.newTmp()
	signBits := c.newTmp()
	isNegative := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp uno double %s, %s\n", isNaN, value, value)
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %s, 0.000000e+00\n", isZero, value)
	fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %s)\n", abs, value)
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %%%s, 0x7FF0000000000000\n", isInfinity, abs)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notNaN, isNaN)
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notZero, isZero)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", c2, notNaN, notZero)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", c0, isNaN, isInfinity)
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, value)
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -9223372036854775808\n", signBits, bits)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", isNegative, signBits)
	c3Word := c.x87StatusBit(isZero, 16384)
	c2Word := c.x87StatusBit(c2, 1024)
	c1Word := c.x87StatusBit(isNegative, 512)
	c0Word := c.x87StatusBit(c0, 256)
	first := c.newTmp()
	second := c.newTmp()
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i16 %s, %s\n", first, c3Word, c2Word)
	fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %s\n", second, first, c1Word)
	fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %s\n", status, second, c0Word)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", status, c.x87StatusSlot)
}

func (c *amd64Ctx) x87StatusBit(condition string, mask int) string {
	word := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %d, i16 0\n", word, condition, mask)
	return "%" + word
}

func (c *amd64Ctx) evalX87F64(op Operand) (string, error) {
	if index, ok := x87OperandReg(op); ok {
		return c.loadX87(index), nil
	}
	return c.evalF64(op)
}

func (c *amd64Ctx) storeX87F64(dst Operand, value string) error {
	if handled, err := c.storeX87NativeFloatingMove(dst, LLVMType("double"), value); handled {
		return err
	}
	if index, ok := x87OperandReg(dst); ok {
		c.storeX87(index, value)
		return nil
	}
	switch dst.Kind {
	case OpFP:
		return c.storeScalarFPFloat(dst.FPOffset, 64, value)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store double %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store double %s, ptr %s, align 1\n", value, p)
		return nil
	default:
		return fmt.Errorf("386: unsupported x87 double destination %s", dst.String())
	}
}

func (c *amd64Ctx) storeX87I16(dst Operand, value string) error {
	switch dst.Kind {
	case OpReg:
		return c.storeRegSized(dst.Reg, I16, value)
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I16, value)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s, align 1\n", value, p)
		return nil
	default:
		return fmt.Errorf("386: unsupported x87 word destination %s", dst.String())
	}
}

func (c *amd64Ctx) storeX87I64(dst Operand, value string) error {
	switch dst.Kind {
	case OpFP:
		return c.storeFPResult(dst.FPOffset, I64, value)
	case OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, ptr %s, align 1\n", value, p)
		return nil
	default:
		return fmt.Errorf("386: unsupported x87 integer destination %s", dst.String())
	}
}

func (c *amd64Ctx) storeHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fnstcw $0\", \"=*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}

func (c *amd64Ctx) loadHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fldcw $0\", \"*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}

func (c *amd64Ctx) roundX87Hardware(slot string) {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fldl $1; frndint; fstpl $0\", \"=*m,*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(double) %s, ptr elementtype(double) %s)\n", slot, slot)
}

func (c *amd64Ctx) convertX87ToI64Hardware() string {
	if c.x87ExactSlot[0] == "" {
		fmt.Fprintf(c.b, "  call void asm sideeffect \"fldl $1; fistpll $0\", \"=*m,*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i64) %s, ptr elementtype(double) %s)\n", c.x87IntegerSlot, c.x87Slot[0])
	} else {
		fmt.Fprintf(c.b, "  call void asm sideeffect \"cmpb $$0, $3; je 1f; fildll $2; jmp 2f; 1: fldl $1; 2: fistpll $0\", \"=*m,*m,*m,*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i64) %s, ptr elementtype(double) %s, ptr elementtype(i64) %s, ptr elementtype(i1) %s)\n",
			c.x87IntegerSlot, c.x87Slot[0], c.x87IntegerValueSlot[0], c.x87ExactSlot[0])
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i64, ptr %s\n", value, c.x87IntegerSlot)
	return "%" + value
}

func (c *amd64Ctx) roundX87Software(value string) string {
	cw := c.newTmp()
	mode := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", cw, c.x87ControlSlot)
	fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, 3072\n", mode, cw)
	down := c.newTmp()
	up := c.newTmp()
	zero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call double @llvm.floor.f64(double %s)\n", down, value)
	fmt.Fprintf(c.b, "  %%%s = call double @llvm.ceil.f64(double %s)\n", up, value)
	fmt.Fprintf(c.b, "  %%%s = call double @llvm.trunc.f64(double %s)\n", zero, value)
	nearest := c.roundNearestEvenX87(value, "%"+down)
	isDown := c.newTmp()
	isUp := c.newTmp()
	isZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %%%s, 1024\n", isDown, mode)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %%%s, 2048\n", isUp, mode)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i16 %%%s, 3072\n", isZero, mode)
	selectDown := c.newTmp()
	selectUp := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %%%s, double %s\n", selectDown, isDown, down, nearest)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %%%s, double %%%s\n", selectUp, isUp, up, selectDown)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %%%s, double %%%s\n", result, isZero, zero, selectUp)
	return "%" + result
}

func (c *amd64Ctx) roundNearestEvenX87(value, floor string) string {
	// Values at or above 2^52 are already integral in binary64. Treat unordered
	// values the same way so NaNs pass through without feeding fptosi.
	abs := c.newTmp()
	large := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call double @llvm.fabs.f64(double %s)\n", abs, value)
	fmt.Fprintf(c.b, "  %%%s = fcmp uge double %%%s, 4.503599627370496e+15\n", large, abs)
	fraction := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fsub double %s, %s\n", fraction, value, floor)
	aboveHalf := c.newTmp()
	tie := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp ogt double %%%s, 5.000000e-01\n", aboveHalf, fraction)
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %%%s, 5.000000e-01\n", tie, fraction)
	floorInt := c.newTmp()
	oddBits := c.newTmp()
	odd := c.newTmp()
	// Only values below 2^52 need a tie-parity calculation. Keep even the
	// discarded large/NaN path free of an out-of-range fptosi operand.
	parityInput := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double 0.000000e+00, double %s\n", parityInput, large, floor)
	fmt.Fprintf(c.b, "  %%%s = fptosi double %%%s to i64\n", floorInt, parityInput)
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", oddBits, floorInt)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", odd, oddBits)
	tieUp := c.newTmp()
	roundUp := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tieUp, tie, odd)
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", roundUp, aboveHalf, tieUp)
	ceil := c.newTmp()
	rounded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fadd double %s, 1.000000e+00\n", ceil, floor)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %%%s, double %s\n", rounded, roundUp, ceil, floor)
	// Arithmetic can turn a negative result rounded to zero into +0. Preserve
	// the source sign to match x87 FRNDINT.
	valueBits := c.newTmp()
	signedZeroBits := c.newTmp()
	signedZero := c.newTmp()
	isZero := c.newTmp()
	withSignedZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", valueBits, value)
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, -9223372036854775808\n", signedZeroBits, valueBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to double\n", signedZero, signedZeroBits)
	fmt.Fprintf(c.b, "  %%%s = fcmp oeq double %%%s, 0.000000e+00\n", isZero, rounded)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %%%s, double %%%s\n", withSignedZero, isZero, signedZero, rounded)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, double %s, double %%%s\n", result, large, value, withSignedZero)
	return "%" + result
}
