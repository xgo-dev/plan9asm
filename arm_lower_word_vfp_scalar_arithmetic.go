package plan9asm

import "fmt"

type armRawVFPScalarArithmetic struct {
	kind        string
	condition   string
	bits        int
	destination int
	lhs         int
	rhs         int
}

// decodeARMRawVFPScalarArithmetic covers the complete classic A32 scalar VFP
// arithmetic family: add, subtract, multiply, negative multiply, divide, and
// the four accumulating multiply forms, for F32/F64 and every executable
// condition and register field.
func decodeARMRawVFPScalarArithmetic(word uint32) (armRawVFPScalarArithmetic, bool) {
	const variable = uint32(0xf0000000 | 0x00400000 | 0x000f0000 | 0x0000f000 | 0x00000100 | 0x00000080 | 0x00000020 | 0x0000000f)
	var kind string
	switch word &^ variable {
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
	case 0x0e000a00:
		kind = "madd"
	case 0x0e000a40:
		kind = "msub"
	case 0x0e100a40:
		kind = "nmadd"
	case 0x0e100a00:
		kind = "nmsub"
	default:
		return armRawVFPScalarArithmetic{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPScalarArithmetic{}, false
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
	return armRawVFPScalarArithmetic{
		kind:        kind,
		condition:   condition,
		bits:        bits,
		destination: destination,
		lhs:         lhs,
		rhs:         rhs,
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

func (c *armCtx) lowerRawVFPScalarArithmetic(form armRawVFPScalarArithmetic) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPScalarArithmetic(form)
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
	switch form.kind {
	case "add":
		result = emitBinary("fadd", lhs, rhs)
	case "sub":
		result = emitBinary("fsub", lhs, rhs)
	case "mul":
		result = emitBinary("fmul", lhs, rhs)
	case "nmul":
		result = emitNeg(emitBinary("fmul", lhs, rhs))
	case "div":
		result = emitBinary("fdiv", lhs, rhs)
	default:
		accumulator, loadErr := c.loadARMRawVFPRegValue(form.destination, form.bits)
		if loadErr != nil {
			return loadErr
		}
		product := emitBinary("fmul", lhs, rhs)
		switch form.kind {
		case "madd":
			result = emitBinary("fadd", accumulator, product)
		case "msub":
			result = emitBinary("fsub", accumulator, product)
		case "nmadd":
			result = emitNeg(emitBinary("fadd", accumulator, product))
		case "nmsub":
			result = emitBinary("fsub", product, accumulator)
		}
	}
	return c.storeARMRawVFPRegValue(form.destination, form.bits, result)
}
