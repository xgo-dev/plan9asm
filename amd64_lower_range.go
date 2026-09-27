package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FloatingRangeSpec struct {
	laneBits int
	scalar   bool
}

// amd64FloatingRangeSpecs is the complete Go 1.27 VRANGE grammar. The
// immediate supplies the comparison and sign modes, so those orthogonal
// dimensions stay data instead of expanding into opcode-specific handlers.
var amd64FloatingRangeSpecs = map[Op]amd64FloatingRangeSpec{
	"VRANGEPS": {laneBits: 32},
	"VRANGEPD": {laneBits: 64},
	"VRANGESS": {laneBits: 32, scalar: true},
	"VRANGESD": {laneBits: 64, scalar: true},
}

func (c *amd64Ctx) lowerFloatingRange(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FloatingRangeSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's range optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar && properties.broadcast {
		return true, false, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("%s %s expects immediate, source2, source1, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s immediate must be an unsigned byte: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[3]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	first, second := ins.Args[1], ins.Args[2]
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if spec.scalar {
		if byteWidth != 16 {
			return true, false, fmt.Errorf("%s %s scalar destination must be an X register: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s packed destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(destination, byteWidth) || !c.isGoEVEXVectorRegister(second, byteWidth) {
		return true, false, fmt.Errorf("%s %s source1 and destination must be same-width Go vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae && !spec.scalar && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s packed SAE is available only for Z registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast {
		if !isAMD64MemoryOperand(first) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source2: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if first.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(first, byteWidth) {
			return true, false, fmt.Errorf("%s %s source2 register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s source2 must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae && first.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s.SAE requires a register source2: %q", c.goarch, baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
	}
	if spec.scalar {
		return c.lowerScalarFloatingRange(spec, properties, ins, first, second, destination, mask)
	}
	return c.lowerPackedFloatingRange(spec, properties, ins, first, second, destination, byteWidth, mask)
}

func (c *amd64Ctx) lowerPackedFloatingRange(spec amd64FloatingRangeSpec, properties amd64BinaryFloatingSuffix, ins Instr, first, second, destination Operand, byteWidth int, mask string) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	source2, err := c.loadPackedCompareLanes(first, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	source1, err := c.loadPackedCompareLanes(second, byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitFloatingRangeBits(lanes, spec.laneBits, source1, source2, uint8(ins.Args[0].Imm))
	if mask != "" {
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarFloatingRange(spec amd64FloatingRangeSpec, properties amd64BinaryFloatingSuffix, ins Instr, first, second, destination Operand, mask string) (bool, bool, error) {
	source2, err := c.loadFloatingScalarBits(first, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	source1, err := c.loadFloatingScalarBits(second, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	source2Vector := c.newTmp()
	source1Vector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", source2Vector, spec.laneBits, spec.laneBits, source2)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", source1Vector, spec.laneBits, spec.laneBits, source1)
	result := c.emitFloatingRangeBits(1, spec.laneBits, "%"+source1Vector, "%"+source2Vector, uint8(ins.Args[0].Imm))
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	secondBytes, err := c.loadX(second.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, secondBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+low, base, mask, properties.zeroing)
}

func (c *amd64Ctx) loadFloatingScalarBits(operand Operand, laneBits int) (string, error) {
	value, err := c.loadFloatingScalarOperand(operand, laneBits)
	if err != nil {
		return "", err
	}
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", bits, amd64FloatingScalarType(laneBits), value, laneBits)
	return "%" + bits, nil
}

// emitFloatingRangeBits follows Intel's range operation in integer bit space
// around one ordered floating comparison. This preserves NaN payloads, quiets
// signaling NaNs, and handles signed zero and equal-magnitude opposite signs.
func (c *amd64Ctx) emitFloatingRangeBits(lanes, laneBits int, source1, source2 string, immediate uint8) string {
	integerType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	floatType := amd64FloatingVectorType(lanes, laneBits)
	predicateType := fmt.Sprintf("<%d x i1>", lanes)
	signBit := uint64(1) << (laneBits - 1)
	absMask := signBit - 1
	quietBit := uint64(0x00400000)
	infinity := uint64(0x7f800000)
	if laneBits == 64 {
		quietBit = uint64(0x0008000000000000)
		infinity = uint64(0x7ff0000000000000)
	}
	signVector := llvmSplatInteger(lanes, laneBits, signBit)
	absVector := llvmSplatInteger(lanes, laneBits, absMask)
	quietVector := llvmSplatInteger(lanes, laneBits, quietBit)
	infinityVector := llvmSplatInteger(lanes, laneBits, infinity)

	abs1, abs2 := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", abs1, integerType, source1, absVector)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", abs2, integerType, source2, absVector)

	compareLeft, compareRight := source1, source2
	if immediate&3 >= 2 {
		compareLeft, compareRight = "%"+abs1, "%"+abs2
	}
	leftFloat, rightFloat := c.newTmp(), c.newTmp()
	ordered := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", leftFloat, integerType, compareLeft, floatType)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", rightFloat, integerType, compareRight, floatType)
	fmt.Fprintf(c.b, "  %%%s = fcmp ole %s %%%s, %%%s\n", ordered, floatType, leftFloat, rightFloat)
	selected := c.newTmp()
	if immediate&1 == 0 {
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", selected, predicateType, ordered, integerType, source1, integerType, source2)
	} else {
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", selected, predicateType, ordered, integerType, source2, integerType, source1)
	}
	result := "%" + selected

	signXor, signDifference, oppositeSigns := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", signXor, integerType, source1, source2)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %s\n", signDifference, integerType, signXor, signVector)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", oppositeSigns, integerType, signDifference)
	if immediate&3 < 2 {
		zero1, zero2, bothZero, oppositeZero := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", zero1, integerType, abs1)
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", zero2, integerType, abs2)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", bothZero, predicateType, zero1, zero2)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", oppositeZero, predicateType, bothZero, oppositeSigns)
		zeroResult := "zeroinitializer"
		if immediate&1 == 0 {
			zeroResult = signVector
		}
		overridden := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", overridden, predicateType, oppositeZero, integerType, zeroResult, integerType, result)
		result = "%" + overridden
	} else {
		equalMagnitude, equalOpposite := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %%%s\n", equalMagnitude, integerType, abs1, abs2)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", equalOpposite, predicateType, equalMagnitude, oppositeSigns)
		tieResult := "%" + abs1
		if immediate&1 == 0 {
			negative := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", negative, integerType, abs1, signVector)
			tieResult = "%" + negative
		}
		overridden := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", overridden, predicateType, equalOpposite, integerType, tieResult, integerType, result)
		result = "%" + overridden
	}

	isNaN1, isNaN2 := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", isNaN1, integerType, abs1, infinityVector)
	fmt.Fprintf(c.b, "  %%%s = icmp ugt %s %%%s, %s\n", isNaN2, integerType, abs2, infinityVector)
	withoutNaN1 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", withoutNaN1, predicateType, isNaN1, integerType, source2, integerType, result)
	withoutQuietNaNs := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %%%s\n", withoutQuietNaNs, predicateType, isNaN2, integerType, source1, integerType, withoutNaN1)
	result = "%" + withoutQuietNaNs

	signMode := immediate >> 2 & 3
	if signMode != 1 {
		magnitude := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", magnitude, integerType, result, absVector)
		switch signMode {
		case 0:
			sourceSign := c.newTmp()
			signed := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", sourceSign, integerType, source1, signVector)
			fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %%%s\n", signed, integerType, magnitude, sourceSign)
			result = "%" + signed
		case 2:
			result = "%" + magnitude
		case 3:
			signed := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", signed, integerType, magnitude, signVector)
			result = "%" + signed
		}
	}

	quiet1, quiet2 := c.newTmp(), c.newTmp()
	quietField1, quietField2 := c.newTmp(), c.newTmp()
	quietClear1, quietClear2 := c.newTmp(), c.newTmp()
	signaling1, signaling2 := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", quiet1, integerType, source1, quietVector)
	fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", quiet2, integerType, source2, quietVector)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", quietField1, integerType, source1, quietVector)
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", quietField2, integerType, source2, quietVector)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", quietClear1, integerType, quietField1)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", quietClear2, integerType, quietField2)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", signaling1, predicateType, isNaN1, quietClear1)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", signaling2, predicateType, isNaN2, quietClear2)
	withSecondSignaling := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %%%s, %s %s\n", withSecondSignaling, predicateType, signaling2, integerType, quiet2, integerType, result)
	withFirstSignaling := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %%%s, %s %%%s\n", withFirstSignaling, predicateType, signaling1, integerType, quiet1, integerType, withSecondSignaling)
	return "%" + withFirstSignaling
}
