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
	return classifyX87Op(op) != x87CatUnknown
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
	if c.goarch != "386" && c.goarch != "amd64" {
		return true, false, fmt.Errorf("%s: x87 instruction %s requires GOARCH=386 or amd64", c.goarch, op)
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
		plan := classifyX87Move(op, ins.Args)
		switch plan.Kind {
		case x87MovePushReg:
			// Go encodes `FMOVD Fi, F0` (including F0, F0) as D9 C0+i (`FLD ST(i)`),
			// pushing a copy of ST(i) onto the x87 stack.
			c.projectX87Status("0", 0x0200)
			return true, false, c.pushX87Value(c.loadX87Value(plan.SrcIdx))
		case x87MoveStoreReg:
			c.projectX87Status("0", 0x0200)
			c.storeX87Value(plan.DstIdx, c.loadX87Value(plan.SrcIdx))
			return true, false, nil
		case x87MoveStoreMem:
			v, err := c.x87ValueToF64(c.loadX87Value(plan.SrcIdx))
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeX87F64(ins.Args[1], v)
		case x87MovePushMem, x87MoveLoadMemToReg:
			f64, err := c.evalF64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			v, err := c.f64ToX87Value(f64)
			if err != nil {
				return true, false, err
			}
			if plan.Kind == x87MovePushMem {
				return true, false, c.pushX87Value(v)
			}
			c.storeX87Value(plan.DstIdx, v)
			return true, false, nil
		default:
			f64, err := c.evalF64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			return true, false, c.storeX87F64(ins.Args[1], f64)
		}

	case "FMOVDP":
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("386 FMOVDP expects src, dst: %q", ins.Raw)
		}
		plan := classifyX87Move(op, ins.Args)
		switch plan.Kind {
		case x87MoveStorePopReg:
			c.projectX87Status("0", 0x0200)
			c.storeX87Value(plan.DstIdx, c.loadX87Value(plan.SrcIdx))
			c.popX87Value()
			return true, false, nil
		case x87MoveStorePopMem:
			v, err := c.x87ValueToF64(c.loadX87Value(plan.SrcIdx))
			if err != nil {
				return true, false, err
			}
			if err := c.storeX87F64(ins.Args[1], v); err != nil {
				return true, false, err
			}
			c.popX87Value()
			return true, false, nil
		default:
			f64, err := c.evalF64(ins.Args[0])
			if err != nil {
				return true, false, err
			}
			if err := c.storeX87F64(ins.Args[1], f64); err != nil {
				return true, false, err
			}
			c.popX87Value()
			return true, false, nil
		}

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
		c.projectX87Status("0", 0x0200)
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
			c.mergeX87ArithStatus(status)
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
		c.projectX87Status("0", 0x0200)
		return true, false, nil

	case "FSQRT":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FSQRT takes no operands: %q", ins.Raw)
		}
		if c.useHardwareX87() {
			res, _, status := c.evaluateX87Native("fsqrt", []x87Value{c.loadX87Value(0)}, 1, 1)
			c.mergeX87ArithStatus(status)
			c.storeX87Value(0, res)
			return true, false, nil
		}
		res, status := c.x87PortableSqrt(c.loadX87Value(0), c.loadX87ControlWord())
		c.mergeX87ArithStatus(status)
		c.storeX87Value(0, res)
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
		eq, lt, uno, exc := c.x87PortableCompareWithFlags(lhs, rhs, true)
		c.mergeX87StickyExceptions(exc)
		c.projectX87Status("0", 0x0200)
		z := c.x87IR("or i1 %s, %s", eq, uno)
		cf := c.x87IR("or i1 %s, %s", lt, uno)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", z, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", cf, c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", uno, c.flagsPFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		c.clearAuxCarryFlag()
		return true, false, nil

	case "FTST":
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("386 FTST takes no operands: %q", ins.Raw)
		}
		eq, lt, uno, exc := c.x87PortableCompareWithFlags(c.loadX87Value(0), x87ZeroValue, false)
		c.mergeX87StickyExceptions(exc)
		c3 := c.x87IR("or i1 %s, %s", eq, uno)
		c0 := c.x87IR("or i1 %s, %s", lt, uno)
		c3w := c.x87IR("select i1 %s, i16 16384, i16 0", c3)
		c2w := c.x87IR("select i1 %s, i16 1024, i16 0", uno)
		c0w := c.x87IR("select i1 %s, i16 256, i16 0", c0)
		s01 := c.x87IR("or i16 %s, %s", c3w, c2w)
		status := c.x87IR("or i16 %s, %s", s01, c0w)
		// Update C3|C2|C1|C0 (0x4700, with C1=0) while preserving TOP (0x3800) and sticky exceptions.
		c.projectX87Status(status, 0x4700)
		return true, false, nil

	case "FSTSW":
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("386 FSTSW expects dst: %q", ins.Raw)
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87StatusSlot)
		return true, false, c.storeX87I16(ins.Args[0], "%"+status)
	}
	return c.lowerX87Ext(op, ins)
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

// adjustX87Top adds delta (modulo 8: -1 on push/FDECSTP, +1 on pop/FINCSTP)
// to the architectural TOP field (bits 13:11, mask 0x3800) of c.x87StatusSlot
// while preserving all other status-word bits.
func (c *amd64Ctx) adjustX87Top(delta int) {
	status := c.x87IR("load i16, ptr %s", c.x87StatusSlot)
	top := c.x87IR("and i16 %s, 7", c.x87IR("lshr i16 %s, 11", status))
	nextTop := c.x87IR("and i16 %s, 7", c.x87IR("add i16 %s, %d", top, delta&7))
	kept := c.x87IR("and i16 %s, %d", status, ^uint16(0x3800))
	merged := c.x87IR("or i16 %s, %s", kept, c.x87IR("shl i16 %s, 11", nextTop))
	fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", merged, c.x87StatusSlot)
}

func (c *amd64Ctx) pushX87Value(value x87Value) error {
	for i := len(c.x87Slot) - 1; i > 0; i-- {
		c.storeX87Value(i, c.loadX87Value(i-1))
	}
	c.storeX87Value(0, value)
	c.adjustX87Top(-1)
	return nil
}

func (c *amd64Ctx) popX87Value() {
	for i := 0; i < len(c.x87Slot)-1; i++ {
		c.storeX87Value(i, c.loadX87Value(i+1))
	}
	c.storeX87Value(len(c.x87Slot)-1, x87ZeroValue)
	c.adjustX87Top(1)
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
	code.WriteString("fnclex; ")
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
	c.emitX87NativeAsm("fnclex; "+instruction+" $2; fnstsw $1; fstpt $0",
		[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}, {c.x87NativeStatus, "i16"}},
		[]x87NativeOperand{{c.x87ScalarScratch, typ}})
	status := c.x87IR("load i16, ptr %s", c.x87NativeStatus)
	c.mergeX87StickyExceptions(status)
	c.projectX87Status("0", 0x0200)
	return x87Value(c.x87IR("load %s, ptr %s", x87ValueType, c.x87ValueScratch[0]))
}

func (c *amd64Ctx) x87NativeToScalar(value x87Value, typ, instruction string) string {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, value, c.x87ValueScratch[1])
	c.emitX87NativeAsm("fnclex; fldt $2; "+instruction+" $0; fnstsw $1",
		[]x87NativeOperand{{c.x87ScalarScratch, typ}, {c.x87NativeStatus, "i16"}},
		[]x87NativeOperand{{c.x87ValueScratch[1], x87ValueType}})
	status := c.x87IR("load i16, ptr %s", c.x87NativeStatus)
	c.mergeX87ArithStatus(status)
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

// mergeX87ArithStatus updates C1 (bit 9, 0x0200, non-sticky) and ORs sticky
// exception flags (bits 0..5, 0x003f: IE/DE/ZE/OE/UE/PE) from status into
// c.x87StatusSlot while preserving TOP (0x3800), C3/C2/C0, and earlier sticky
// exception bits.
func (c *amd64Ctx) mergeX87ArithStatus(status string) {
	prev := c.x87IR("load i16, ptr %s", c.x87StatusSlot)
	clearedC1 := c.x87IR("and i16 %s, %d", prev, ^uint16(0x0200))
	excAndC1 := c.x87IR("and i16 %s, %d", status, 0x023f)
	merged := c.x87IR("or i16 %s, %s", clearedC1, excAndC1)
	fmt.Fprintf(c.b, "  store i16 %s, ptr %s\n", merged, c.x87StatusSlot)
}

// mergeX87StickyExceptions ORs sticky x87 exception bits (bits 0..5, 0x003f)
// into c.x87StatusSlot while preserving all other status-word bits.
func (c *amd64Ctx) mergeX87StickyExceptions(exc string) {
	prev := c.x87IR("load i16, ptr %s", c.x87StatusSlot)
	masked := c.x87IR("and i16 %s, %d", exc, 0x003f)
	merged := c.x87IR("or i16 %s, %s", prev, masked)
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
	quietBitMask := uint64(1) << (fractionBits - 1)
	isSNaN := c.x87IR("and i1 %s, %s", isNaN, c.x87IR("icmp eq i64 %s, 0", c.x87IR("and i64 %s, %d", fraction, quietBitMask)))
	quiet := c.x87IR("or i64 %s, 4611686018427387904", significand)
	significand = c.x87IR("select i1 %s, i64 %s, i64 %s", isNaN, quiet, significand)
	normalExponent = c.x87IR("select i1 %s, i64 32767, i64 %s", special, normalExponent)
	isSubnormal := c.x87IR("icmp eq i64 %s, 0", exponent)
	isDenorm := c.x87IR("and i1 %s, %s", isSubnormal, c.x87IR("xor i1 %s, true", zero))
	excIE := c.x87IR("select i1 %s, i16 1, i16 0", isSNaN)
	excDE := c.x87IR("select i1 %s, i16 2, i16 0", isDenorm)
	c.mergeX87StickyExceptions(c.x87IR("or i16 %s, %s", excIE, excDE))
	c.projectX87Status("0", 0x0200)
	significand = c.x87IR("select i1 %s, i64 %s, i64 %s", isSubnormal, subnormal, significand)
	exponent = c.x87IR("select i1 %s, i64 %s, i64 %s", isSubnormal, subExponent, normalExponent)
	exponent = c.x87IR("trunc i64 %s to i16", c.x87IR("or i64 %s, %s", exponent, sign))
	return c.packX87(significand, exponent), nil
}

func (c *amd64Ctx) x87PortableRoundedShiftWithFlags(value, shift, negative, cw string) (result, inexact, roundedUp string) {
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
	doInc := c.x87IR("and i1 %s, %s", c.x87IR("select i1 %s, i1 %s, i1 %s", isNearest, nearest, c.x87IR("or i1 %s, %s", down, up)), discarded)
	inc := c.x87IR("zext i1 %s to i64", doInc)
	return c.x87IR("add i64 %s, %s", quotient, inc), discarded, doInc
}

func (c *amd64Ctx) x87PortableRound(value x87Value, cw string) (x87Value, error) {
	sig, se := c.partsX87(value)
	exp := c.x87IR("zext i16 %s to i32", c.x87IR("and i16 %s, 32767", se))
	zeroExp := c.x87IR("icmp eq i32 %s, 0", exp)
	effExp := c.x87IR("select i1 %s, i32 1, i32 %s", zeroExp, exp)
	shift := c.x87IR("sub i32 16446, %s", effExp)
	neg := c.x87IR("icmp slt i16 %s, 0", se)
	mag, inexact, roundedUp := c.x87PortableRoundedShiftWithFlags(sig, shift, neg, cw)
	leading := c.x87IR("call i64 @llvm.ctlz.i64(i64 %s, i1 false)", mag)
	rSig := c.x87IR("shl i64 %s, %s", mag, c.x87IR("and i64 %s, 63", leading))
	rExp := c.x87IR("select i1 %s, i64 0, i64 %s", c.x87IR("icmp eq i64 %s, 0", mag), c.x87IR("sub i64 16446, %s", leading))
	rSE := c.x87IR("or i16 %s, %s", c.x87IR("trunc i64 %s to i16", rExp), c.x87IR("and i16 %s, 32768", se))
	rounded := c.packX87(rSig, rSE)
	alreadyInt := c.x87IR("icmp uge i32 %s, 16446", exp)
	selected := c.x87IR("select i1 %s, %s %s, %s %s", alreadyInt, x87ValueType, value, x87ValueType, rounded)
	nan := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i32 %s, 32767", exp), c.x87IR("icmp ne i64 %s, 0", c.x87IR("and i64 %s, 9223372036854775807", sig)))
	snan := c.x87IR("and i1 %s, %s", nan, c.x87IR("icmp eq i64 %s, 0", c.x87IR("and i64 %s, 4611686018427387904", sig)))
	selected = c.x87IR("select i1 %s, %s %s, %s %s", nan, x87ValueType, c.packX87(c.x87IR("or i64 %s, 4611686018427387904", sig), se), x87ValueType, selected)
	unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zeroExp))
	denorm := c.x87IR("and i1 %s, %s", zeroExp, c.x87IR("icmp ne i64 %s, 0", sig))
	notAlready := c.x87IR("and i1 %s, %s", c.x87IR("xor i1 %s, true", alreadyInt), c.x87IR("xor i1 %s, true", unsup))
	peCond := c.x87IR("and i1 %s, %s", notAlready, inexact)
	c1Cond := c.x87IR("and i1 %s, %s", notAlready, roundedUp)
	ieCond := c.x87IR("or i1 %s, %s", unsup, snan)
	st := c.x87IR("or i16 %s, %s",
		c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 1, i16 0", ieCond), c.x87IR("select i1 %s, i16 2, i16 0", denorm)),
		c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 32, i16 0", peCond), c.x87IR("select i1 %s, i16 512, i16 0", c1Cond)))
	c.mergeX87ArithStatus(st)
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
	rounded, inexact, roundedUp := c.x87PortableRoundedShiftWithFlags(norm, c.x87IR("add i32 %s, %d", extra, 64-precision), neg, cw)
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
	isSNaN := c.x87IR("and i1 %s, %s", c.x87IR("and i1 %s, %s", special, isNaN), c.x87IR("icmp eq i64 %s, 0", c.x87IR("and i64 %s, 4611686018427387904", sig)))
	payload = c.x87IR("select i1 %s, i64 %s, i64 0", isNaN, c.x87IR("or i64 %s, %d", c.x87IR("lshr i64 %s, %d", payload, 64-precision), uint64(1)<<(precision-2)))
	packed = c.x87IR("select i1 %s, i64 %s, i64 %s", special, c.x87IR("or i64 %s, %s", c.x87IR("or i64 %s, %d", payload, infBits), sign), packed)
	unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zeroExp))
	isZero := c.x87IR("and i1 %s, %s", zeroExp, c.x87IR("icmp eq i64 %s, 0", sig))
	isFiniteNZ := c.x87IR("and i1 %s, %s", c.x87IR("xor i1 %s, true", c.x87IR("or i1 %s, %s", special, unsup)), c.x87IR("xor i1 %s, true", isZero))
	oeCond := c.x87IR("and i1 %s, %s", isFiniteNZ, overflow)
	ueCond := c.x87IR("and i1 %s, %s", c.x87IR("and i1 %s, %s", isFiniteNZ, c.x87IR("icmp eq i32 %s, 0", finalExp)), inexact)
	peCond := c.x87IR("or i1 %s, %s", oeCond, c.x87IR("and i1 %s, %s", isFiniteNZ, inexact))
	c1Cond := c.x87IR("or i1 %s, %s", c.x87IR("and i1 %s, %s", oeCond, inf), c.x87IR("and i1 %s, %s", c.x87IR("and i1 %s, %s", isFiniteNZ, c.x87IR("xor i1 %s, true", overflow)), roundedUp))
	ieCond := c.x87IR("or i1 %s, %s", unsup, isSNaN)
	st := c.x87IR("or i16 %s, %s",
		c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 1, i16 0", ieCond), c.x87IR("select i1 %s, i16 8, i16 0", oeCond)),
		c.x87IR("or i16 %s, %s", c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 16, i16 0", ueCond), c.x87IR("select i1 %s, i16 32, i16 0", peCond)), c.x87IR("select i1 %s, i16 512, i16 0", c1Cond)))
	c.mergeX87ArithStatus(st)
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
	c.projectX87Status("0", 0x0200)
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
	rounded, inexact, roundedUp := c.x87PortableRoundedShiftWithFlags(sig, shift, neg, cw)
	bound := uint64(1) << (bits - 1)
	valid := c.x87IR("select i1 %s, i1 %s, i1 %s", neg, c.x87IR("icmp ule i64 %s, %d", rounded, bound), c.x87IR("icmp ult i64 %s, %d", rounded, bound))
	valid = c.x87IR("and i1 %s, %s", valid, c.x87IR("icmp ule i32 %s, %d", effExp, 16383+bits-1))
	valid = c.x87IR("and i1 %s, %s", valid, c.x87IR("or i1 %s, %s", zeroExp, c.x87IR("icmp slt i64 %s, 0", sig)))
	ieCond := c.x87IR("xor i1 %s, true", valid)
	peCond := c.x87IR("and i1 %s, %s", valid, inexact)
	c1Cond := c.x87IR("and i1 %s, %s", valid, roundedUp)
	st := c.x87IR("or i16 %s, %s",
		c.x87IR("select i1 %s, i16 1, i16 0", ieCond),
		c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 32, i16 0", peCond), c.x87IR("select i1 %s, i16 512, i16 0", c1Cond)))
	c.mergeX87ArithStatus(st)
	res := c.x87IR("select i1 %s, i64 %s, i64 %s", neg, c.x87IR("sub i64 0, %s", rounded), rounded)
	res = c.x87IR("select i1 %s, i64 %s, i64 %d", valid, res, bound)
	if bits != 64 {
		res = c.x87IR("trunc i64 %s to i%d", res, bits)
	}
	return res, nil
}

func (c *amd64Ctx) x87PortableCompareWithFlags(left, right x87Value, unorderedCmp bool) (equal, less, unordered, exc string) {
	lSig, lSE := c.partsX87(left)
	rSig, rSE := c.partsX87(right)
	var exps, negs, invs, snans, unsps, zeros, dens [2]string
	for i, p := range [][2]string{{lSig, lSE}, {rSig, rSE}} {
		sig, se := p[0], p[1]
		exp := c.x87IR("and i16 %s, 32767", se)
		zExp := c.x87IR("icmp eq i16 %s, 0", exp)
		exps[i] = c.x87IR("select i1 %s, i16 1, i16 %s", zExp, exp)
		negs[i] = c.x87IR("icmp slt i16 %s, 0", se)
		unsup := c.x87IR("and i1 %s, %s", c.x87IR("icmp sge i64 %s, 0", sig), c.x87IR("xor i1 %s, true", zExp))
		nan := c.x87IR("and i1 %s, %s", c.x87IR("icmp eq i16 %s, 32767", exp), c.x87IR("icmp ne i64 %s, 9223372036854775808", sig))
		snan := c.x87IR("and i1 %s, %s", nan, c.x87IR("icmp eq i64 %s, 0", c.x87IR("and i64 %s, 4611686018427387904", sig)))
		unsps[i] = unsup
		snans[i] = snan
		invs[i] = c.x87IR("or i1 %s, %s", unsup, nan)
		zSig := c.x87IR("icmp eq i64 %s, 0", sig)
		zeros[i] = c.x87IR("and i1 %s, %s", zSig, zExp)
		dens[i] = c.x87IR("and i1 %s, %s", c.x87IR("xor i1 %s, true", zSig), zExp)
	}
	unordered = c.x87IR("or i1 %s, %s", invs[0], invs[1])
	ordered := c.x87IR("xor i1 %s, true", unordered)
	var ieCond string
	if unorderedCmp {
		// FUCOM*/FUCOMI*: raise IE only on SNaN or unsupported encoding (not QNaN).
		ieCond = c.x87IR("or i1 %s, %s", c.x87IR("or i1 %s, %s", snans[0], snans[1]), c.x87IR("or i1 %s, %s", unsps[0], unsps[1]))
	} else {
		// FCOM*/FCOMI*/FTST: raise IE on any NaN or unsupported encoding.
		ieCond = unordered
	}
	deCond := c.x87IR("or i1 %s, %s", dens[0], dens[1])
	exc = c.x87IR("or i16 %s, %s", c.x87IR("select i1 %s, i16 1, i16 0", ieCond), c.x87IR("select i1 %s, i16 2, i16 0", deCond))
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
