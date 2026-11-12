package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// lowerFloatingCompare implements the complete Go 1.27 floating-point
// immediate-compare family: legacy CMP{PD,PS,SD,SS}, the VEX vector-result
// forms, and the EVEX K-result forms of VCMP{PD,PS,SD,SS}.
func (c *amd64Ctx) lowerFloatingCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86FloatCompareSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("floating compare dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86FloatCompareProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return true, false, c.emitNativeFloatingCompare(ins, form)
}

func amd64FloatingCompareProperties(op string) (elemBits int, packed, vector, ok bool) {
	switch op {
	case "CMPPD":
		return 64, true, false, true
	case "CMPPS":
		return 32, true, false, true
	case "CMPSD":
		return 64, false, false, true
	case "CMPSS":
		return 32, false, false, true
	case "VCMPPD":
		return 64, true, true, true
	case "VCMPPS":
		return 32, true, true, true
	case "VCMPSD":
		return 64, false, true, true
	case "VCMPSS":
		return 32, false, true, true
	default:
		return 0, false, false, false
	}
}

func amd64LegacyFloatingCompareImmediate(arg Operand) (int64, bool) {
	if arg.Kind == OpImm {
		return arg.Imm, true
	}
	// The pre-Go-1.5 x86 assembler wrote CMP{PD,PS,SD,SS} predicates as a
	// bare decimal operand. Keep this compatibility confined to the legacy
	// compare family's predicate position instead of accepting bare integers
	// as immediates throughout the parser.
	var text string
	switch arg.Kind {
	case OpIdent:
		text = arg.Ident
	case OpSym:
		text = arg.Sym
	default:
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64)
	return value, err == nil
}

func (c *amd64Ctx) isGoLegacyXReg(r Reg) bool {
	index, ok := amd64ParseXReg(r)
	if !ok {
		return false
	}
	if c.goarch == "386" {
		return index < 8
	}
	return index < 16
}

func dstArgOperand(r Reg) Operand {
	return Operand{Kind: OpReg, Reg: r}
}

func amd64VEXVectorRegister(op Operand, byteWidth int) bool {
	if op.Kind != OpReg || amd64VectorByteWidth(op.Reg) != byteWidth {
		return false
	}
	index, ok := amd64VectorRegisterIndex(op.Reg, byteWidth)
	return ok && index < 16
}

func amd64EVEXVectorRegister(op Operand, byteWidth int) bool {
	if op.Kind != OpReg || amd64VectorByteWidth(op.Reg) != byteWidth {
		return false
	}
	index, ok := amd64VectorRegisterIndex(op.Reg, byteWidth)
	return ok && index < 32
}

func amd64VectorRegisterIndex(r Reg, byteWidth int) (int, bool) {
	switch byteWidth {
	case 16:
		return amd64ParseXReg(r)
	case 32:
		return amd64ParseYReg(r)
	case 64:
		return amd64ParseZReg(r)
	default:
		return 0, false
	}
}

func amd64FloatingComparePredicate(immediate uint8) string {
	return [...]string{
		"oeq", "olt", "ole", "uno", "une", "uge", "ugt", "ord",
		"ueq", "ult", "ule", "false", "one", "oge", "ogt", "true",
		"oeq", "olt", "ole", "uno", "une", "uge", "ugt", "ord",
		"ueq", "ult", "ule", "false", "one", "oge", "ogt", "true",
	}[immediate&31]
}

func (c *amd64Ctx) loadFloatingVectorOperand(op Operand, byteWidth, lanes, elemBits int) (string, error) {
	bytesValue, err := c.loadPackedCompareBytes(op, byteWidth)
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, byteWidth, bytesValue, amd64FloatingVectorType(lanes, elemBits))
	return "%" + value, nil
}

func (c *amd64Ctx) loadFloatingScalarOperand(op Operand, elemBits int) (string, error) {
	if elemBits == 64 {
		return c.evalF64(op)
	}
	return c.evalF32(op)
}

func (c *amd64Ctx) splatFloatingScalar(value string, lanes, elemBits int) string {
	vectorType := amd64FloatingVectorType(lanes, elemBits)
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", inserted, vectorType, result, amd64FloatingScalarType(elemBits), value, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) packFloatingCompareMask(compared string, lanes int) string {
	if lanes == 1 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", wide, compared)
		return "%" + wide
	}
	packedType := fmt.Sprintf("i%d", lanes)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %s to %s\n", packed, lanes, compared, packedType)
	if lanes == 64 {
		return "%" + packed
	}
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext %s %%%s to i64\n", wide, packedType, packed)
	return "%" + wide
}

func amd64FloatingScalarType(elemBits int) string {
	if elemBits == 64 {
		return "double"
	}
	return "float"
}

func amd64FloatingVectorType(lanes, elemBits int) string {
	return fmt.Sprintf("<%d x %s>", lanes, amd64FloatingScalarType(elemBits))
}
