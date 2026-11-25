package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// x87Value is a private 80-bit IEEE 754 binary80 register carrier ({ i64, i16 }):
// 64-bit significand with explicit integer bit + 16-bit sign/exponent.
type x87Value string

const (
	x87ValueType = "{ i64, i16 }"
	x87ZeroValue = x87Value("zeroinitializer")
)

func isX87Op(op asm.Op) bool {
	switch op {
	case "FMOVD", "FMOVDP", "FMOVV", "FMOVVP", "FXCHD", "FADDDP",
		"FDIVD", "FMULD", "FMULDP", "FSTCW", "FLDCW", "FRNDINT",
		"FABS", "FCHS", "FUCOMI", "FTST", "FSTSW", "FLD1", "FLDZ",
		"FSQRT", "FINIT", "FCLEX", "FNOP":
		return true
	default:
		return false
	}
}

func (c *amd64Ctx) requireX87SoftwareControlInit(op asm.Op) error {
	if c.useHardwareX87() || c.x87CWInitialized {
		return nil
	}
	return fmt.Errorf("%w: result initialization: %s requires initialized x87 control word in software mode", asm.ErrProbeNeedsContext, op)
}

func (c *amd64Ctx) lowerX87(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	if !isX87Op(op) {
		return false, false, nil
	}
	if c.goarch != "386" {
		return true, false, fmt.Errorf("amd64: x87 instruction %s requires GOARCH=386", op)
	}

	switch op {
	case "FINIT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FINIT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fninit", "~{st},~{st(1)},~{st(2)},~{st(3)},~{st(4)},~{st(5)},~{st(6)},~{st(7)},~{fpsr}"()`)
		}
		for i := range c.x87Slot {
			c.storeX87Value(i, x87ZeroValue)
		}
		fmt.Fprintf(c.b, "  store i16 895, ptr %s\n", c.x87ControlSlot)
		fmt.Fprintf(c.b, "  store i16 0, ptr %s\n", c.x87StatusSlot)
		c.x87CWInitialized = true
		return true, false, nil

	case "FCLEX":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FCLEX takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			fmt.Fprintln(c.b, `  call void asm sideeffect "fnclex", "~{fpsr}"()`)
		}
		status := c.newTmp()
		cc := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, 32512\n", cc, status)
		fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", cc, c.x87StatusSlot)
		return true, false, nil

	case "FNOP":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FNOP takes no operands: %q", ins.Raw)
		}
		return true, false, nil

	case "FMOVD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVD expects src, dst: %q", ins.Raw)
		}
		if srcIdx, srcIsF := x87OperandReg(ins.Args[0]); srcIsF {
			if dstIdx, dstIsF := x87OperandReg(ins.Args[1]); dstIsF {
				c.storeX87Value(dstIdx, c.loadX87Value(srcIdx))
				return true, false, nil
			}
			v, err := c.x87ValueToF64(c.loadX87Value(srcIdx))
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeX87F64(ins.Args[1], v)
		}
		f64, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if dstIdx, dstIsF := x87OperandReg(ins.Args[1]); dstIsF {
			v, err := c.f64ToX87Value(f64)
			if err != nil {
				return true, false, err
			}
			if dstIdx == 0 {
				return true, false, c.pushX87Value(v)
			}
			c.storeX87Value(dstIdx, v)
			return true, false, nil
		}
		return true, false, c.storeX87F64(ins.Args[1], f64)

	case "FMOVDP":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVDP expects src, dst: %q", ins.Raw)
		}
		if srcIdx, srcIsF := x87OperandReg(ins.Args[0]); srcIsF {
			if dstIdx, dstIsF := x87OperandReg(ins.Args[1]); dstIsF {
				c.storeX87Value(dstIdx, c.loadX87Value(srcIdx))
				c.popX87Value()
				return true, false, nil
			}
			v, err := c.x87ValueToF64(c.loadX87Value(srcIdx))
			if err != nil {
				return true, false, err
			}
			if err := c.storeX87F64(ins.Args[1], v); err != nil {
				return true, false, err
			}
			c.popX87Value()
			return true, false, nil
		}
		f64, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		if err := c.storeX87F64(ins.Args[1], f64); err != nil {
			return true, false, err
		}
		c.popX87Value()
		return true, false, nil

	case "FMOVV":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVV expects src, dst: %q", ins.Raw)
		}
		if idx, ok := x87OperandReg(ins.Args[1]); !ok || idx != 0 {
			return true, false, fmt.Errorf("386 FMOVV expects F0 destination: %q", ins.Raw)
		}
		v, err := c.evalIntSized(ins.Args[0], asm.I64)
		if err != nil {
			return true, false, err
		}
		x87v, err := c.i64ToX87Value(v)
		if err != nil {
			return true, false, err
		}
		return true, false, c.pushX87Value(x87v)

	case "FMOVVP":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVVP expects src, dst: %q", ins.Raw)
		}
		if index, ok := x87OperandReg(ins.Args[0]); !ok || index != 0 {
			return true, false, fmt.Errorf("386 FMOVVP expects F0 source: %q", ins.Raw)
		}
		if err := c.requireX87SoftwareControlInit(op); err != nil {
			return true, false, err
		}
		val := c.loadX87Value(0)
		var iv string
		if c.useHardwareX87() {
			iv = c.x87NativeToSigned(val, 64)
		} else {
			cw := c.loadX87ControlWord()
			iv, err = c.x87PortableToSigned(val, 64, cw)
			if err != nil {
				return true, false, err
			}
		}
		if err := c.storeX87I64(ins.Args[1], iv); err != nil {
			return true, false, err
		}
		c.popX87Value()
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
		av := c.loadX87Value(a)
		b := c.loadX87Value(bv)
		c.storeX87Value(a, b)
		c.storeX87Value(bv, av)
		return true, false, nil

	case "FDIVD", "FMULD":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalX87F64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalX87F64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		if op == "FDIVD" {
			fmt.Fprintf(c.b, "  %%%s = fdiv double %s, %s\n", out, dst, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", out, dst, src)
		}
		return true, false, c.storeX87F64(ins.Args[1], "%"+out)

	case "FADDDP", "FMULDP":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 %s expects src, dst: %q", op, ins.Raw)
		}
		src, err := c.evalX87F64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		dst, err := c.evalX87F64(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		if op == "FADDDP" {
			fmt.Fprintf(c.b, "  %%%s = fadd double %s, %s\n", out, dst, src)
		} else {
			fmt.Fprintf(c.b, "  %%%s = fmul double %s, %s\n", out, dst, src)
		}
		if err := c.storeX87F64(ins.Args[1], "%"+out); err != nil {
			return true, false, err
		}
		c.popX87Value()
		return true, false, nil

	case "FSTCW":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("386 FSTCW expects dst: %q", ins.Raw)
		}
		if err := c.requireX87SoftwareControlInit(op); err != nil {
			return true, false, err
		}
		if c.useHardwareX87() {
			c.storeHardwareX87ControlWord()
		}
		cw := c.loadX87ControlWord()
		return true, false, c.storeX87I16(ins.Args[0], cw)

	case "FLDCW":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("386 FLDCW expects src: %q", ins.Raw)
		}
		cw, err := c.evalIntSized(ins.Args[0], asm.I16)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", cw, c.x87ControlSlot)
		c.x87CWInitialized = true
		if c.useHardwareX87() {
			c.loadHardwareX87ControlWord()
		}
		return true, false, nil

	case "FRNDINT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FRNDINT takes no operands: %q", ins.Raw)
		}
		if err := c.requireX87SoftwareControlInit(op); err != nil {
			return true, false, err
		}
		if c.useHardwareX87() {
			res, _, status := c.evaluateX87Native("frndint", []x87Value{c.loadX87Value(0)}, 1, 1)
			c.projectX87Status(status, 0x0200)
			c.storeX87Value(0, res)
			return true, false, nil
		}
		cw := c.loadX87ControlWord()
		rounded, err := c.x87PortableRound(c.loadX87Value(0), cw)
		if err != nil {
			return true, false, err
		}
		c.storeX87Value(0, rounded)
		return true, false, nil

	case "FABS", "FCHS":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
		}
		sig, se := c.partsX87(c.loadX87Value(0))
		if op == "FABS" {
			se = c.x87IR("and i16 %s, 32767", se)
		} else {
			se = c.x87IR("xor i16 %s, 32768", se)
		}
		c.storeX87Value(0, c.packX87(sig, se))
		return true, false, nil

	case "FSQRT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FSQRT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			res, _, status := c.evaluateX87Native("fsqrt", []x87Value{c.loadX87Value(0)}, 1, 1)
			c.projectX87Status(status, 0x0200)
			c.storeX87Value(0, res)
			return true, false, nil
		}
		v, err := c.x87ValueToF64(c.loadX87Value(0))
		if err != nil {
			return true, false, err
		}
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call double @llvm.sqrt.f64(double %s)\n", out, v)
		x87v, err := c.f64ToX87Value("%" + out)
		if err != nil {
			return true, false, err
		}
		c.storeX87Value(0, x87v)
		return true, false, nil

	case "FUCOMI":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FUCOMI expects lhs, rhs: %q", ins.Raw)
		}
		lhs, err := c.evalX87Value(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		rhs, err := c.evalX87Value(ins.Args[1])
		if err != nil {
			return true, false, err
		}
		eq, lt, uno := c.x87PortableCompare(lhs, rhs)
		z := c.x87IR("or i1 %s, %s", eq, uno)
		cf := c.x87IR("or i1 %s, %s", lt, uno)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		return true, false, nil

	case "FTST":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FTST takes no operands: %q", ins.Raw)
		}
		eq, lt, uno := c.x87PortableCompare(c.loadX87Value(0), x87ZeroValue)
		c3 := c.x87IR("or i1 %s, %s", eq, uno)
		c0 := c.x87IR("or i1 %s, %s", lt, uno)
		c3w := c.x87IR("select i1 %s, i16 16384, i16 0", c3)
		c2w := c.x87IR("select i1 %s, i16 1024, i16 0", uno)
		c0w := c.x87IR("select i1 %s, i16 256, i16 0", c0)
		s01 := c.x87IR("or i16 %s, %s", c3w, c2w)
		status := c.x87IR("or i16 %s, %s", s01, c0w)
		fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", status, c.x87StatusSlot)
		return true, false, nil

	case "FSTSW":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("386 FSTSW expects dst: %q", ins.Raw)
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+status)

	case "FLD1":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FLD1 takes no operands: %q", ins.Raw)
		}
		return true, false, c.pushX87Value(c.packX87("9223372036854775808", "16383"))

	case "FLDZ":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FLDZ takes no operands: %q", ins.Raw)
		}
		return true, false, c.pushX87Value(x87ZeroValue)
	}
	return false, false, nil
}

func x87OperandReg(op asm.Operand) (int, bool) {
	if op.Kind != asm.OpReg {
		return 0, false
	}
	return amd64ParseX87Reg(op.Reg)
}

func (c *amd64Ctx) x87IR(format string, args ...any) string {
	v := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s\n", v, fmt.Sprintf(format, args...))
	return "%" + v
}

func (c *amd64Ctx) packX87(significand, signExponent string) x87Value {
	low := c.x87IR("insertvalue %s zeroinitializer, i64 %s, 0", x87ValueType, significand)
	return x87Value(c.x87IR("insertvalue %s %s, i16 %s, 1", x87ValueType, low, signExponent))
}

func (c *amd64Ctx) partsX87(value x87Value) (significand, signExponent string) {
	return c.x87IR("extractvalue %s %s, 0", x87ValueType, value),
		c.x87IR("extractvalue %s %s, 1", x87ValueType, value)
}

func (c *amd64Ctx) loadX87ControlWord() string {
	return c.x87IR("load i16, ptr %s", c.x87ControlSlot)
}

func (c *amd64Ctx) loadX87Value(index int) x87Value {
	return x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87Slot[index]))
}

func (c *amd64Ctx) storeX87Value(index int, value x87Value) {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, value, c.x87Slot[index])
}

func (c *amd64Ctx) pushX87Value(value x87Value) error {
	for i := len(c.x87Slot) - 1; i > 0; i-- {
		c.storeX87Value(i, c.loadX87Value(i-1))
	}
	c.storeX87Value(0, value)
	return nil
}

func (c *amd64Ctx) popX87Value() {
	for i := 0; i < len(c.x87Slot)-1; i++ {
		c.storeX87Value(i, c.loadX87Value(i+1))
	}
	c.storeX87Value(len(c.x87Slot)-1, x87ZeroValue)
}

func (c *amd64Ctx) f64ToX87Value(f64 string) (x87Value, error) {
	if c.useHardwareX87() {
		return c.x87NativeFromScalar(f64, "double", "fldl"), nil
	}
	return c.x87PortableFromFloat(f64, 64)
}

func (c *amd64Ctx) x87ValueToF64(val x87Value) (string, error) {
	if c.useHardwareX87() {
		return c.x87NativeToScalar(val, "double", "fstpl"), nil
	}
	return c.x87PortableToFloat(val, 64, c.loadX87ControlWord())
}

func (c *amd64Ctx) i64ToX87Value(iv string) (x87Value, error) {
	if c.useHardwareX87() {
		return c.x87NativeFromScalar(iv, "i64", "fildll"), nil
	}
	return c.x87PortableFromSigned(iv, 64)
}

func (c *amd64Ctx) evalX87Value(op asm.Operand) (x87Value, error) {
	if index, ok := x87OperandReg(op); ok {
		return c.loadX87Value(index), nil
	}
	f64, err := c.evalF64(op)
	if err != nil {
		return "", err
	}
	return c.f64ToX87Value(f64)
}

func (c *amd64Ctx) evalX87F64(op asm.Operand) (string, error) {
	if index, ok := x87OperandReg(op); ok {
		return c.x87ValueToF64(c.loadX87Value(index))
	}
	return c.evalF64(op)
}

func (c *amd64Ctx) storeX87F64(dst asm.Operand, value string) error {
	if index, ok := x87OperandReg(dst); ok {
		v, err := c.f64ToX87Value(value)
		if err != nil {
			return err
		}
		c.storeX87Value(index, v)
		return nil
	}
	switch dst.Kind {
	case asm.OpFP:
		return c.storeFPResult(dst.FPOffset, asm.LLVMType("double"), value)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store double %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case asm.OpSym:
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

func (c *amd64Ctx) storeX87I16(dst asm.Operand, value string) error {
	switch dst.Kind {
	case asm.OpReg:
		return c.storeRegSized(dst.Reg, asm.I16, value)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i16 %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case asm.OpSym:
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

func (c *amd64Ctx) storeX87I64(dst asm.Operand, value string) error {
	switch dst.Kind {
	case asm.OpFP:
		return c.storeFPResult(dst.FPOffset, asm.I64, value)
	case asm.OpMem:
		p, ptrType, err := c.ptrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store i64 %s, %s %s, align 1\n", value, ptrType, p)
		return nil
	case asm.OpSym:
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

// --- Hardware 80-bit x87 lowering ---

type x87NativeOperand struct {
	pointer string
	typ     string
}

func (c *amd64Ctx) emitX87NativeAsm(code string, outputs, inputs []x87NativeOperand) {
	constraints := make([]string, 0, len(outputs)+len(inputs)+1)
	arguments := make([]string, 0, len(outputs)+len(inputs))
	for index, op := range append(append([]x87NativeOperand(nil), outputs...), inputs...) {
		constraint := "*m"
		if index < len(outputs) {
			constraint = "=*m"
		}
		constraints = append(constraints, constraint)
		arguments = append(arguments, fmt.Sprintf("ptr elementtype(%s) %s", op.typ, op.pointer))
	}
	constraints = append(constraints, "~{st},~{st(1)},~{st(2)},~{st(3)},~{st(4)},~{st(5)},~{st(6)},~{st(7)},~{fpsr},~{memory}")
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n", code, strings.Join(constraints, ","), strings.Join(arguments, ", "))
}

func (c *amd64Ctx) evaluateX87Native(instruction string, values []x87Value, results, remaining int) (x87Value, x87Value, string) {
	outputs := []x87NativeOperand{
		{c.x87ValueScratch[0], x87ValueType},
		{c.x87ValueScratch[1], x87ValueType},
		{c.x87NativeStatus, "i16"},
	}
	inputs := make([]x87NativeOperand, len(values))
	for i, v := range values {
		fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, v, c.x87ValueScratch[i+1])
		inputs[i] = x87NativeOperand{c.x87ValueScratch[i+1], x87ValueType}
	}
	var code strings.Builder
	for i := len(inputs) - 1; i >= 0; i-- {
		fmt.Fprintf(&code, "fldt $%d; ", len(outputs)+i)
	}
	code.WriteString(instruction)
	code.WriteString("; fnstsw $2")
	for i := 0; i < results; i++ {
		fmt.Fprintf(&code, "; fstpt $%d", i)
	}
	for i := results; i < remaining; i++ {
		code.WriteString("; fstp %st(0)")
	}
	c.emitX87NativeAsm(code.String(), outputs, inputs)
	first, second := x87ZeroValue, x87ZeroValue
	if results > 0 {
		first = x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0]))
	}
	if results > 1 {
		second = x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[1]))
	}
	status := c.x87IR("load i16, ptr %s", c.x87NativeStatus)
	return first, second, status
}

func (c *amd64Ctx) x87NativeFromScalar(value, typ, instruction string) x87Value {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", typ, value, c.x87ScalarScratch)
	c.emitX87NativeAsm(instruction+" $1; fstpt $0",
		[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}},
		[]x87NativeOperand{{c.x87ScalarScratch, typ}})
	return x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0]))
}

func (c *amd64Ctx) x87NativeToScalar(value x87Value, typ, instruction string) string {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, value, c.x87ValueScratch[1])
	c.emitX87NativeAsm("fldt $1; "+instruction+" $0",
		[]x87NativeOperand{{c.x87ScalarScratch, typ}},
		[]x87NativeOperand{{c.x87ValueScratch[1], x87ValueType}})
	return c.x87IR("load %s, ptr %s", typ, c.x87ScalarScratch)
}

func (c *amd64Ctx) x87NativeToSigned(value x87Value, bits int) string {
	switch bits {
	case 16:
		return c.x87NativeToScalar(value, "i16", "fistps")
	case 32:
		return c.x87NativeToScalar(value, "i32", "fistpl")
	default:
		return c.x87NativeToScalar(value, "i64", "fistpll")
	}
}

func (c *amd64Ctx) projectX87Status(status string, mask int) {
	prev := c.x87IR("load i16, ptr %s", c.x87StatusSlot)
	kept := c.x87IR("and i16 %s, %d", prev, ^uint16(mask))
	changed := c.x87IR("and i16 %s, %d", status, mask)
	merged := c.x87IR("or i16 %s, %s", kept, changed)
	fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", merged, c.x87StatusSlot)
}

func (c *amd64Ctx) storeHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fnstcw $0\", \"=*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}

func (c *amd64Ctx) loadHardwareX87ControlWord() {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"fldcw $0\", \"*m,~{dirflag},~{fpsr},~{flags}\"(ptr elementtype(i16) %s)\n", c.x87ControlSlot)
}

// --- Portable bit-exact 80-bit software x87 lowering (pure integer IR) ---

func (c *amd64Ctx) x87PortableFromFloat(value string, bits int) (x87Value, error) {
	precision, bias, maximum, typ := 53, 1023, 2047, "double"
	if bits == 32 {
		precision, bias, maximum, typ = 24, 127, 255, "float"
	} else if bits != 64 {
		return "", fmt.Errorf("unsupported x87 floating input width %d", bits)
	}
	fractionBits := precision - 1
	raw := c.x87IR("bitcast %s %s to i%d", typ, value, bits)
	if bits == 32 {
		raw = c.x87IR("zext i32 %s to i64", raw)
	}
	sign := c.x87IR("shl i64 %s, 15", c.x87IR("lshr i64 %s, %d", raw, bits-1))
	exponent := c.x87IR("and i64 %s, %d", c.x87IR("lshr i64 %s, %d", raw, fractionBits), maximum)
	fraction := c.x87IR("and i64 %s, %d", raw, uint64(1)<<fractionBits-1)
	leading := c.x87IR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", fraction)
	safeLeading := c.x87IR("and i64 %s, 63", leading)
	subnormal := c.x87IR("shl i64 %s, %s", fraction, safeLeading)
	subExponent := c.x87IR("sub i64 %d, %s", 16383+64-bias-fractionBits, leading)
	zero := c.x87IR("icmp eq i64 %s, 0", fraction)
	subExponent = c.x87IR("select i1 %s, i64 0, i64 %s", zero, subExponent)
	significand := c.x87IR("shl i64 %s, %d", c.x87IR("or i64 %s, %d", fraction, uint64(1)<<fractionBits), 64-precision)
	normalExponent := c.x87IR("add i64 %s, %d", exponent, 16383-bias)
	special := c.x87IR("icmp eq i64 %s, %d", exponent, maximum)
	isNaN := c.x87IR("and i1 %s, %s", special, c.x87IR("xor i1 %s, true", zero))
	quiet := c.x87IR("or i64 %s, 4611686018427387904", significand)
	significand = c.x87IR("select i1 %s, i64 %s, i64 %s", isNaN, quiet, significand)
	normalExponent = c.x87IR("select i1 %s, i64 32767, i64 %s", special, normalExponent)
	isSubnormal := c.x87IR("icmp eq i64 %s, 0", exponent)
	significand = c.x87IR("select i1 %s, i64 %s, i64 %s", isSubnormal, subnormal, significand)
	exponent = c.x87IR("select i1 %s, i64 %s, i64 %s", isSubnormal, subExponent, normalExponent)
	exponent = c.x87IR("trunc i64 %s to i16", c.x87IR("or i64 %s, %s", exponent, sign))
	return c.packX87(significand, exponent), nil
}

func (c *amd64Ctx) x87PortableRoundedShift(value, shift, negative, cw string) string {
	wide := c.x87IR("icmp uge i32 %s, 64", shift)
	bounded := c.x87IR("zext i32 %s to i64", c.x87IR("select i1 %s, i32 63, i32 %s", wide, shift))
	quotient := c.x87IR("select i1 %s, i64 0, i64 %s", wide, c.x87IR("lshr i64 %s, %s", value, bounded))
	mask := c.x87IR("select i1 %s, i64 -1, i64 %s", wide, c.x87IR("sub i64 %s, 1", c.x87IR("shl i64 1, %s", bounded)))
	remainder := c.x87IR("and i64 %s, %s", value, mask)
	discarded := c.x87IR("icmp ne i64 %s, 0", remainder)
	halfShift := c.x87IR("zext i32 %s to i64", c.x87IR("and i32 %s, 63", c.x87IR("sub i32 %s, 1", shift)))
	half := c.x87IR("shl i64 1, %s", halfShift)
	above := c.x87IR("icmp ugt i64 %s, %s", remainder, half)
	tie := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i64 %s, %s", remainder, half), c.x87IR("icmp ne i64 %s, 0", c.x87IR("and i64 %s, 1", quotient)))
	nearest := c.x87IR("and i1 %s, %s", c.x87IR("or i1 %s, %s", above, tie), c.x87IR("icmp ule i32 %s, 64", shift))
	rounding := c.x87IR("and i16 %s, 3", c.x87IR("lshr i16 %s, 10", cw))
	isNearest := c.x87IR("icmp eq i16 %s, 0", rounding)
	down := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 1", rounding), negative)
	up := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 2", rounding), c.x87IR("xor i1 %s, true", negative))
	inc := c.x87IR("zext i1 %s to i64", c.x87IR("and i1 %s, %s", c.x87IR("select i1 %s, i1 %s, i1 %s", isNearest, nearest, c.x87IR("or i1 %s, %s", down, up)), discarded))
	return c.x87IR("add i64 %s, %s", quotient, inc)
}

func (c *amd64Ctx) x87PortableRound(value x87Value, cw string) (x87Value, error) {
	sig, se := c.partsX87(value)
	exp := c.x87IR("zext i16 %s to i32", c.x87IR("and i16 %s, 32767", se))
	zeroExp := c.x87IR("icmp eq i32 %s, 0", exp)
	effExp := c.x87IR("select i1 %s, i32 1, i32 %s", zeroExp, exp)
	shift := c.x87IR("sub i32 16446, %s", effExp)
	neg := c.x87IR("icmp slt i16 %s, 0", se)
	mag := c.x87PortableRoundedShift(sig, shift, neg, cw)
	leading := c.x87IR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", mag)
	rSig := c.x87IR("shl i64 %s, %s", mag, c.x87IR("and i64 %s, 63", leading))
	rExp := c.x87IR("select i1 %s, i64 0, i64 %s", c.x87IR("icmp eq i64 %s, 0", mag), c.x87IR("sub i64 16446, %s", leading))
	rSE := c.x87IR("or i16 %s, %s", c.x87IR("trunc i64 %s to i16", rExp), c.x87IR("and i16 %s, 32768", se))
	rounded := c.packX87(rSig, rSE)
	selected := c.x87IR("select i1 %s, %s %s, %s %s", c.x87IR("icmp uge i32 %s, 16446", exp), x87ValueType, value, x87ValueType, rounded)
	nan := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i32 %s, 32767", exp), c.x87IR("icmp ne i64 %s, 0", c.x87IR("and i64 %s, 9223372036854775807", sig)))
	selected = c.x87IR("select i1 %s, %s %s, %s %s", nan, x87ValueType, c.packX87(c.x87IR("or i64 %s, 4611686018427387904", sig), se), x87ValueType, selected)
	unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zeroExp))
	return x87Value(c.x87IR("select i1 %s, %s %s, %s %s", unsup, x87ValueType, c.packX87("13835058055282163712", "65535"), x87ValueType, selected)), nil
}

func (c *amd64Ctx) x87PortableToFloat(value x87Value, bits int, cw string) (string, error) {
	precision, bias, maximum, typ := 53, 1023, 2047, "double"
	if bits == 32 {
		precision, bias, maximum, typ = 24, 127, 255, "float"
	} else if bits != 64 {
		return "", fmt.Errorf("unsupported x87 floating result width %d", bits)
	}
	sig, se := c.partsX87(value)
	exp := c.x87IR("zext i16 %s to i32", c.x87IR("and i16 %s, 32767", se))
	neg := c.x87IR("icmp slt i16 %s, 0", se)
	zeroExp := c.x87IR("icmp eq i32 %s, 0", exp)
	effExp := c.x87IR("select i1 %s, i32 1, i32 %s", zeroExp, exp)
	leading := c.x87IR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", sig)
	norm := c.x87IR("shl i64 %s, %s", sig, c.x87IR("and i64 %s, 63", leading))
	effExp = c.x87IR("sub i32 %s, %s", effExp, c.x87IR("trunc i64 %s to i32", leading))
	outExp := c.x87IR("sub i32 %s, %d", effExp, 16383-bias)
	subnormal := c.x87IR("icmp sle i32 %s, 0", outExp)
	extra := c.x87IR("select i1 %s, i32 %s, i32 0", subnormal, c.x87IR("sub i32 1, %s", outExp))
	rounded := c.x87PortableRoundedShift(norm, c.x87IR("add i32 %s, %d", extra, 64-precision), neg, cw)
	carry := c.x87IR("icmp uge i64 %s, %d", rounded, uint64(1)<<precision)
	sigRes := c.x87IR("select i1 %s, i64 %s, i64 %s", carry, c.x87IR("lshr i64 %s, 1", rounded), rounded)
	normExp := c.x87IR("add i32 %s, %s", outExp, c.x87IR("zext i1 %s to i32", carry))
	subExp := c.x87IR("zext i1 %s to i32", c.x87IR("icmp uge i64 %s, %d", rounded, uint64(1)<<(precision-1)))
	finalExp := c.x87IR("select i1 %s, i32 %s, i32 %s", subnormal, subExp, normExp)
	overflow := c.x87IR("icmp sge i32 %s, %d", finalExp, maximum)
	frac := c.x87IR("and i64 %s, %d", sigRes, uint64(1)<<(precision-1)-1)
	packed := c.x87IR("or i64 %s, %s", c.x87IR("shl i64 %s, %d", c.x87IR("zext i32 %s to i64", finalExp), precision-1), frac)
	rounding := c.x87IR("and i16 %s, 3", c.x87IR("lshr i16 %s, 10", cw))
	inf := c.x87IR("or i1 %s, %s",
		c.x87IR("or i1 %s, %s",
			c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 1", rounding), neg),
			c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 2", rounding), c.x87IR("xor i1 %s, true", neg))),
		c.x87IR("icmp eq i16 %s, 0", rounding))
	infBits := uint64(maximum) << (precision - 1)
	packed = c.x87IR("select i1 %s, i64 %s, i64 %s", overflow, c.x87IR("select i1 %s, i64 %d, i64 %d", inf, infBits, infBits-1), packed)
	sign := c.x87IR("select i1 %s, i64 %d, i64 0", neg, uint64(1)<<(bits-1))
	packed = c.x87IR("or i64 %s, %s", packed, sign)
	special := c.x87IR("icmp eq i32 %s, 32767", exp)
	payload := c.x87IR("and i64 %s, 9223372036854775807", sig)
	isNaN := c.x87IR("icmp ne i64 %s, 0", payload)
	payload = c.x87IR("select i1 %s, i64 %s, i64 0", isNaN, c.x87IR("or i64 %s, %d", c.x87IR("lshr i64 %s, %d", payload, 64-precision), uint64(1)<<(precision-2)))
	packed = c.x87IR("select i1 %s, i64 %s, i64 %s", special, c.x87IR("or i64 %s, %s", c.x87IR("or i64 %s, %d", payload, infBits), sign), packed)
	unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zeroExp))
	indef := uint64(1)<<(bits-1) | infBits | uint64(1)<<(precision-2)
	packed = c.x87IR("select i1 %s, i64 %d, i64 %s", unsup, indef, packed)
	if bits == 32 {
		packed = c.x87IR("trunc i64 %s to i32", packed)
	}
	return c.x87IR("bitcast i%d %s to %s", bits, packed, typ), nil
}

func (c *amd64Ctx) x87PortableFromSigned(value string, bits int) (x87Value, error) {
	if bits != 16 && bits != 32 && bits != 64 {
		return "", fmt.Errorf("unsupported x87 signed input width %d", bits)
	}
	if bits != 64 {
		value = c.x87IR("sext i%d %s to i64", bits, value)
	}
	neg := c.x87IR("icmp slt i64 %s, 0", value)
	mag := c.x87IR("select i1 %s, i64 %s, i64 %s", neg, c.x87IR("sub i64 0, %s", value), value)
	leading := c.x87IR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", mag)
	sig := c.x87IR("shl i64 %s, %s", mag, c.x87IR("and i64 %s, 63", leading))
	exp := c.x87IR("select i1 %s, i64 0, i64 %s", c.x87IR("icmp eq i64 %s, 0", mag), c.x87IR("sub i64 16446, %s", leading))
	se := c.x87IR("trunc i64 %s to i16", c.x87IR("or i64 %s, %s", exp, c.x87IR("select i1 %s, i64 32768, i64 0", neg)))
	return c.packX87(sig, se), nil
}

func (c *amd64Ctx) x87PortableToSigned(value x87Value, bits int, cw string) (string, error) {
	if bits != 16 && bits != 32 && bits != 64 {
		return "", fmt.Errorf("unsupported x87 signed result width %d", bits)
	}
	sig, se := c.partsX87(value)
	neg := c.x87IR("icmp slt i16 %s, 0", se)
	exp := c.x87IR("zext i16 %s to i32", c.x87IR("and i16 %s, 32767", se))
	zeroExp := c.x87IR("icmp eq i32 %s, 0", exp)
	effExp := c.x87IR("select i1 %s, i32 1, i32 %s", zeroExp, exp)
	shift := c.x87IR("sub i32 16446, %s", effExp)
	shift = c.x87IR("select i1 %s, i32 0, i32 %s", c.x87IR("icmp slt i32 %s, 0", shift), shift)
	rounded := c.x87PortableRoundedShift(sig, shift, neg, cw)
	bound := uint64(1) << (bits - 1)
	valid := c.x87IR("select i1 %s, i1 %s, i1 %s", neg, c.x87IR("icmp ule i64 %s, %d", rounded, bound), c.x87IR("icmp ult i64 %s, %d", rounded, bound))
	valid = c.x87IR("and i1 %s, %s", valid, c.x87IR("icmp ule i32 %s, %d", effExp, 16383+bits-1))
	valid = c.x87IR("and i1 %s, %s", valid, c.x87IR("or i1 %s, %s", zeroExp, c.x87IR("icmp slt i64 %s, 0", sig)))
	res := c.x87IR("select i1 %s, i64 %s, i64 %s", neg, c.x87IR("sub i64 0, %s", rounded), rounded)
	res = c.x87IR("select i1 %s, i64 %s, i64 %d", valid, res, bound)
	if bits != 64 {
		res = c.x87IR("trunc i64 %s to i%d", res, bits)
	}
	return res, nil
}

func (c *amd64Ctx) x87PortableCompare(left, right x87Value) (equal, less, unordered string) {
	lSig, lSE := c.partsX87(left)
	rSig, rSE := c.partsX87(right)
	var exps, negs, invs, zeros [2]string
	for i, p := range [][2]string{{lSig, lSE}, {rSig, rSE}} {
		sig, se := p[0], p[1]
		exp := c.x87IR("and i16 %s, 32767", se)
		zExp := c.x87IR("icmp eq i16 %s, 0", exp)
		exps[i] = c.x87IR("select i1 %s, i16 1, i16 %s", zExp, exp)
		negs[i] = c.x87IR("icmp slt i16 %s, 0", se)
		unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zExp))
		nan := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 32767", exp), c.x87IR("icmp ne i64 %s, 9223372036854775808", sig))
		invs[i] = c.x87IR("or i1 %s, %s", unsup, nan)
		zeros[i] = c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i64 %s, 0", sig), zExp)
	}
	unordered = c.x87IR("or i1 %s, %s", invs[0], invs[1])
	ordered := c.x87IR("xor i1 %s, true", unordered)
	eqExp := c.x87IR("icmp eq i16 %s, %s", exps[0], exps[1])
	eqMag := c.x87IR("and i1 %s, %s", eqExp, c.x87IR("icmp eq i64 %s, %s", lSig, rSig))
	diffSign := c.x87IR("xor i1 %s, %s", negs[0], negs[1])
	bothZero := c.x87IR("and i1 %s, %s", zeros[0], zeros[1])
	equal = c.x87IR("and i1 %s, %s", c.x87IR("or i1 %s, %s", c.x87IR("and i1 %s, %s", eqMag, c.x87IR("xor i1 %s, true", diffSign)), bothZero), ordered)
	lMagLt := c.x87IR("select i1 %s, i1 %s, i1 %s", eqExp, c.x87IR("icmp ult i64 %s, %s", lSig, rSig), c.x87IR("icmp ult i16 %s, %s", exps[0], exps[1]))
	rMagLt := c.x87IR("select i1 %s, i1 %s, i1 %s", eqExp, c.x87IR("icmp ugt i64 %s, %s", lSig, rSig), c.x87IR("icmp ugt i16 %s, %s", exps[0], exps[1]))
	less = c.x87IR("select i1 %s, i1 %s, i1 %s", diffSign, negs[0], c.x87IR("select i1 %s, i1 %s, i1 %s", negs[0], rMagLt, lMagLt))
	less = c.x87IR("and i1 %s, %s", c.x87IR("and i1 %s, %s", less, c.x87IR("xor i1 %s, true", bothZero)), ordered)
	return
}
