package plan9asm

import (
	"fmt"
	"strings"
)

type armVFPScalarArithmeticForm struct {
	kind        string
	condition   string
	bits        int
	destination int
	lhs         int
	rhs         int
	fused       bool
}

func armNamedVFPArithmetic(op string) (armVFPScalarArithmeticForm, bool) {
	form := armVFPScalarArithmeticForm{bits: 32}
	if strings.HasSuffix(op, "D") {
		form.bits = 64
	}
	switch op {
	case "ADDF", "ADDD":
		form.kind = "add"
	case "SUBF", "SUBD":
		form.kind = "sub"
	case "MULF", "MULD":
		form.kind = "mul"
	case "NMULF", "NMULD":
		form.kind = "nmul"
	case "DIVF", "DIVD":
		form.kind = "div"
	case "MULAF", "MULAD", "FMULAF", "FMULAD":
		form.kind = "madd"
	case "MULSF", "MULSD", "FMULSF", "FMULSD":
		form.kind = "msub"
	case "NMULAF", "NMULAD", "FNMULAF", "FNMULAD":
		form.kind = "nmadd"
	case "NMULSF", "NMULSD", "FNMULSF", "FNMULSD":
		form.kind = "nmsub"
	default:
		return armVFPScalarArithmeticForm{}, false
	}
	form.fused = strings.HasPrefix(op, "F")
	return form, true
}

func (form armVFPScalarArithmeticForm) accumulates() bool {
	switch form.kind {
	case "madd", "msub", "nmadd", "nmsub":
		return true
	default:
		return false
	}
}

func parseARMScalarFloatArithmetic(op, condition string, ins Instr) (armVFPScalarArithmeticForm, bool, error) {
	form, matched := armNamedVFPArithmetic(op)
	if !matched {
		return form, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return form, true, err
	}
	if len(ins.Args) != 3 && (len(ins.Args) != 2 || form.accumulates()) {
		if form.accumulates() {
			return form, true, fmt.Errorf("arm %s expects Fsrc1, Fsrc2, Faccumulator: %q", op, ins.Raw)
		}
		return form, true, fmt.Errorf("arm %s expects Fsrc,Fdst or Fsrc1,Fsrc2,Fdst: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || !isARMFReg(arg.Reg) {
			return form, true, fmt.Errorf("arm %s accepts only floating registers: %q", op, ins.Raw)
		}
	}
	// Go writes Vm before Vn. In its two-operand form Vn is also Vd.
	form.rhs = armNamedVFPRegisterNumber(ins.Args[0].Reg, form.bits)
	form.lhs = armNamedVFPRegisterNumber(ins.Args[1].Reg, form.bits)
	form.destination = armNamedVFPRegisterNumber(ins.Args[len(ins.Args)-1].Reg, form.bits)
	form.condition = condition
	return form, true, nil
}

// A32 scalar VFP arithmetic has a common register field layout for both
// widths and every condition. VFPv4 adds fused accumulating operations.
func decodeARMRawVFPScalarArithmetic(word uint32) (armVFPScalarArithmeticForm, bool) {
	const variable = uint32(0xf0000000 | 0x00400000 | 0x000f0000 | 0x0000f000 | 0x00000100 | 0x00000080 | 0x00000020 | 0x0000000f)
	var kind string
	operation := word &^ variable
	switch operation {
	case 0x0e300a00:
		kind = "add"
	case 0x0e300a40:
		kind = "sub"
	case 0x0e200a00:
		kind = "mul"
	case 0x0e200a40:
		kind = "nmul"
	case 0x0e800a00:
		kind = "div"
	case 0x0e000a00, 0x0ea00a00:
		kind = "madd"
	case 0x0e000a40, 0x0ea00a40:
		kind = "msub"
	case 0x0e100a40, 0x0e900a40:
		kind = "nmadd"
	case 0x0e100a00, 0x0e900a00:
		kind = "nmsub"
	default:
		return armVFPScalarArithmeticForm{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armVFPScalarArithmeticForm{}, false
	}
	bits := 32
	destination := int(word>>12) & 15
	lhs := int(word>>16) & 15
	rhs := int(word) & 15
	if word>>8&1 != 0 {
		bits = 64
		destination += int(word>>22&1) * 16
		lhs += int(word>>7&1) * 16
		rhs += int(word>>5&1) * 16
	} else {
		destination = destination*2 + int(word>>22&1)
		lhs = lhs*2 + int(word>>7&1)
		rhs = rhs*2 + int(word>>5&1)
	}
	encoding := operation >> 20 & 0xf
	return armVFPScalarArithmeticForm{
		kind:        kind,
		condition:   condition,
		bits:        bits,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
		fused:       encoding == 9 || encoding == 10,
	}, true
}

func (c *armCtx) storeARMRawVFPRegValue(number, bits int, value string) error {
	encoded := c.newTmp()
	if bits == 32 {
		fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", encoded, value)
		return c.storeARMRawSingleBits(number, "%"+encoded, "")
	}
	fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", encoded, value)
	return c.storeFReg(armRawVFPBackingReg(number, 64), "%"+encoded)
}

func (c *armCtx) lowerVFPScalarArithmetic(form armVFPScalarArithmeticForm) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerVFPScalarArithmetic(form)
		})
	}
	lhs, err := c.loadARMRawVFPRegValue(form.lhs, form.bits)
	if err != nil {
		return err
	}
	rhs, err := c.loadARMRawVFPRegValue(form.rhs, form.bits)
	if err != nil {
		return err
	}
	floatType := "float"
	if form.bits == 64 {
		floatType = "double"
	}
	emitBinary := func(operation, left, right string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", name, operation, floatType, left, right)
		return "%" + name
	}
	emitNeg := func(value string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", name, floatType, value)
		return "%" + name
	}

	var result string
	if form.accumulates() {
		accumulator, loadErr := c.loadARMRawVFPRegValue(form.destination, form.bits)
		if loadErr != nil {
			return loadErr
		}
		negateProduct := form.kind == "msub" || form.kind == "nmadd"
		if form.kind == "nmadd" || form.kind == "nmsub" {
			accumulator = emitNeg(accumulator)
		}
		if form.fused {
			if negateProduct {
				lhs = emitNeg(lhs)
			}
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fma.f%d(%s %s, %s %s, %s %s)\n",
				name, floatType, form.bits, floatType, lhs, floatType, rhs, floatType, accumulator)
			result = "%" + name
		} else {
			product := emitBinary("fmul", lhs, rhs)
			if negateProduct {
				product = emitNeg(product)
			}
			// Negate operands before adding so exact cancellation has the
			// ARM zero sign, including for the negative accumulating forms.
			result = emitBinary("fadd", accumulator, product)
		}
	} else if form.kind == "nmul" {
		result = emitNeg(emitBinary("fmul", lhs, rhs))
	} else {
		result = emitBinary("f"+form.kind, lhs, rhs)
	}
	return c.storeARMRawVFPRegValue(form.destination, form.bits, result)
}
