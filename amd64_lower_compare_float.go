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
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	elemBits, packed, vector, recognized := amd64FloatingCompareProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if !vector {
		return c.lowerLegacyFloatingCompare(baseOp, suffix, elemBits, packed, ins)
	}
	return c.lowerVectorFloatingCompare(baseOp, suffix, elemBits, packed, ins)
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

func (c *amd64Ctx) lowerLegacyFloatingCompare(baseOp, suffix string, elemBits int, packed bool, ins Instr) (bool, bool, error) {
	if suffix != "" {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's yxcmpi table: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects X/m, X, signed-imm8: %q", baseOp, ins.Raw)
	}
	immediate, ok := amd64LegacyFloatingCompareImmediate(ins.Args[2])
	if !ok {
		return true, false, fmt.Errorf("amd64 %s expects X/m, X, signed-imm8: %q", baseOp, ins.Raw)
	}
	if immediate < -128 || immediate > 127 {
		return true, false, fmt.Errorf("amd64 %s immediate is outside Go 1.27's signed-imm8 class: %q", baseOp, ins.Raw)
	}
	if !c.isGoLegacyXReg(ins.Args[1].Reg) {
		return true, false, fmt.Errorf("amd64 %s destination is outside the Go 1.27 X-register class for %s: %q", baseOp, c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind == OpReg && !c.isGoLegacyXReg(ins.Args[0].Reg) {
		return true, false, fmt.Errorf("amd64 %s register source is outside the Go 1.27 X-register class for %s: %q", baseOp, c.goarch, ins.Raw)
	}
	if ins.Args[0].Kind != OpReg && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s first operand must be X or memory: %q", baseOp, ins.Raw)
	}

	predicate := amd64FloatingComparePredicate(uint8(immediate) & 7)
	if packed {
		return true, false, c.emitFloatingCompareVector(elemBits, 16, ins.Args[0], ins.Args[1], ins.Args[1].Reg, predicate, false)
	}
	return true, false, c.emitFloatingCompareScalarVector(elemBits, ins.Args[0], ins.Args[1], ins.Args[1].Reg, predicate)
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

func (c *amd64Ctx) lowerVectorFloatingCompare(baseOp, suffix string, elemBits int, packed bool, ins Instr) (bool, bool, error) {
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("%s %s is absent from Go 1.27's 386 assembler forms: %q", c.goarch, baseOp, ins.Raw)
	}
	if suffix != "" && suffix != "BCST" && suffix != "SAE" {
		return true, false, fmt.Errorf("amd64 %s suffix is absent from its Go 1.27 EVEX encoding: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects unsigned-imm8, src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 %s first operand must be Go 1.27's unsigned-imm8 class: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be a vector or K register: %q", baseOp, ins.Raw)
	}
	predicate := amd64FloatingComparePredicate(uint8(ins.Args[0].Imm) & 31)

	if _, isK := amd64ParseKReg(dstArg.Reg); !isK {
		return c.lowerVEXFloatingCompareVectorResult(baseOp, suffix, elemBits, packed, predicate, ins)
	}
	return c.lowerEVEXFloatingCompareMaskResult(baseOp, suffix, elemBits, packed, predicate, ins)
}

func (c *amd64Ctx) lowerVEXFloatingCompareVectorResult(baseOp, suffix string, elemBits int, packed bool, predicate string, ins Instr) (bool, bool, error) {
	if suffix != "" || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s VEX vector-result form has no mask or suffix: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[3].Reg
	byteWidth := amd64VectorByteWidth(dst)
	if !packed && byteWidth != 16 {
		return true, false, fmt.Errorf("amd64 %s scalar VEX form requires an X destination: %q", baseOp, ins.Raw)
	}
	if packed && byteWidth != 16 && byteWidth != 32 {
		return true, false, fmt.Errorf("amd64 %s packed VEX form requires an X or Y destination: %q", baseOp, ins.Raw)
	}
	if !amd64VEXVectorRegister(ins.Args[2], byteWidth) || !amd64VEXVectorRegister(dstArgOperand(dst), byteWidth) {
		return true, false, fmt.Errorf("amd64 %s VEX source and destination registers must match and be numbered 0-15: %q", baseOp, ins.Raw)
	}
	if ins.Args[1].Kind == OpReg {
		if !amd64VEXVectorRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s VEX first source must match the destination width and be numbered 0-15: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s VEX first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}
	if packed {
		return true, false, c.emitFloatingCompareVector(elemBits, byteWidth, ins.Args[1], ins.Args[2], dst, predicate, false)
	}
	return true, false, c.emitFloatingCompareScalarVector(elemBits, ins.Args[1], ins.Args[2], dst, predicate)
}

func (c *amd64Ctx) lowerEVEXFloatingCompareMaskResult(baseOp, suffix string, elemBits int, packed bool, predicate string, ins Instr) (bool, bool, error) {
	dst := ins.Args[len(ins.Args)-1].Reg
	if len(ins.Args) == 5 {
		mask := ins.Args[3]
		if mask.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		index, ok := amd64ParseKReg(mask.Reg)
		if !ok || index == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
	}
	second := ins.Args[2]
	if second.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s EVEX second source must be a vector register: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(second.Reg)
	if !packed && byteWidth != 16 {
		return true, false, fmt.Errorf("amd64 %s scalar EVEX form requires an X second source: %q", baseOp, ins.Raw)
	}
	if packed && byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("amd64 %s packed EVEX form requires an X, Y, or Z second source: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(second, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s EVEX second source register is invalid: %q", baseOp, ins.Raw)
	}
	first := ins.Args[1]
	if first.Kind == OpReg {
		if !amd64EVEXVectorRegister(first, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s EVEX first source must match the second source width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("amd64 %s EVEX first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}

	broadcast := suffix == "BCST"
	if broadcast && (!packed || !isAMD64MemoryOperand(first)) {
		return true, false, fmt.Errorf("amd64 %s.BCST requires a packed EVEX memory source: %q", baseOp, ins.Raw)
	}
	if suffix == "SAE" {
		if isAMD64MemoryOperand(first) || (packed && byteWidth != 64) {
			return true, false, fmt.Errorf("amd64 %s.SAE requires the Go 1.27 EVEX register-source width: %q", baseOp, ins.Raw)
		}
	}

	lanes := 1
	var compared string
	var err error
	if packed {
		lanes = byteWidth * 8 / elemBits
		compared, err = c.compareFloatingVector(elemBits, byteWidth, first, second, predicate, broadcast)
	} else {
		compared, err = c.compareFloatingScalar(elemBits, first, second, predicate)
	}
	if err != nil {
		return true, false, err
	}
	result := c.packFloatingCompareMask(compared, lanes)
	if len(ins.Args) == 5 {
		writeMask, err := c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", masked, result, writeMask)
		result = "%" + masked
	}
	return true, false, c.storeK(dst, result)
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

func (c *amd64Ctx) emitFloatingCompareVector(elemBits, byteWidth int, first, second Operand, dst Reg, predicate string, broadcast bool) error {
	compared, err := c.compareFloatingVector(elemBits, byteWidth, first, second, predicate, broadcast)
	if err != nil {
		return err
	}
	lanes := byteWidth * 8 / elemBits
	allBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %s to <%d x i%d>\n", allBits, lanes, compared, lanes, elemBits)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <%d x i8>\n", bytesValue, lanes, elemBits, allBits, byteWidth)
	return c.storeVectorBytes(dst, byteWidth, "%"+bytesValue)
}

func (c *amd64Ctx) compareFloatingVector(elemBits, byteWidth int, first, second Operand, predicate string, broadcast bool) (string, error) {
	lanes := byteWidth * 8 / elemBits
	vectorType := amd64FloatingVectorType(lanes, elemBits)
	var firstValue string
	var err error
	if broadcast {
		firstValue, err = c.loadFloatingScalarOperand(first, elemBits)
		if err == nil {
			firstValue = c.splatFloatingScalar(firstValue, lanes, elemBits)
		}
	} else {
		firstValue, err = c.loadFloatingVectorOperand(first, byteWidth, lanes, elemBits)
	}
	if err != nil {
		return "", err
	}
	secondValue, err := c.loadFloatingVectorOperand(second, byteWidth, lanes, elemBits)
	if err != nil {
		return "", err
	}
	compared := c.newTmp()
	// Go/Plan 9 lists the Intel r/m source first: compare second with first.
	fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", compared, predicate, vectorType, secondValue, firstValue)
	return "%" + compared, nil
}

func (c *amd64Ctx) emitFloatingCompareScalarVector(elemBits int, first, second Operand, dst Reg, predicate string) error {
	compared, err := c.compareFloatingScalar(elemBits, first, second, predicate)
	if err != nil {
		return err
	}
	mask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext i1 %s to i%d\n", mask, compared, elemBits)
	secondBytes, err := c.loadPackedCompareBytes(second, 16)
	if err != nil {
		return err
	}
	lanes := 128 / elemBits
	integerVector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", integerVector, secondBytes, lanes, elemBits)
	updated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %%%s, i%d %%%s, i32 0\n", updated, lanes, elemBits, integerVector, elemBits, mask)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", bytesValue, lanes, elemBits, updated)
	return c.storeX(dst, "%"+bytesValue)
}

func (c *amd64Ctx) compareFloatingScalar(elemBits int, first, second Operand, predicate string) (string, error) {
	firstValue, err := c.loadFloatingScalarOperand(first, elemBits)
	if err != nil {
		return "", err
	}
	secondValue, err := c.loadFloatingScalarOperand(second, elemBits)
	if err != nil {
		return "", err
	}
	compared := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", compared, predicate, amd64FloatingScalarType(elemBits), secondValue, firstValue)
	return "%" + compared, nil
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
