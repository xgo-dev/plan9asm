package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedNumericKind uint8

const (
	amd64PackedNumericFloat amd64PackedNumericKind = iota
	amd64PackedNumericSigned
	amd64PackedNumericUnsigned
)

type amd64PackedNumericShape struct {
	sourceBytes      int
	destinationBytes int
	lanes            int
}

type amd64PackedNumericConversionSpec struct {
	sourceKind      amd64PackedNumericKind
	destinationKind amd64PackedNumericKind
	sourceBits      int
	destinationBits int
	truncate        bool
	explicit        string
	shapes          []amd64PackedNumericShape
}

var (
	amd64PackedNumericSame32 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 4},
		{sourceBytes: 32, destinationBytes: 32, lanes: 8},
		{sourceBytes: 64, destinationBytes: 64, lanes: 16},
	}
	amd64PackedNumericSame64 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 2},
		{sourceBytes: 32, destinationBytes: 32, lanes: 4},
		{sourceBytes: 64, destinationBytes: 64, lanes: 8},
	}
	amd64PackedNumericWiden32To64 = []amd64PackedNumericShape{
		{sourceBytes: 16, destinationBytes: 16, lanes: 2},
		{sourceBytes: 16, destinationBytes: 32, lanes: 4},
		{sourceBytes: 32, destinationBytes: 64, lanes: 8},
	}
)

// amd64PackedNumericConversionSpecs describes the complete Go 1.27 EVEX
// packed numeric-conversion family not covered by the legacy/VEX conversion
// handlers. Source/destination element types and physical width shapes remain
// independent axes, avoiding one lowerer per mnemonic and register width.
var amd64PackedNumericConversionSpecs = map[Op]amd64PackedNumericConversionSpec{
	"VCVTPD2QQ":    {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTPD2UQQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTTPD2QQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 64, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame64},
	"VCVTTPD2UQQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame64},
	"VCVTPS2UDQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 32, explicit: "round", shapes: amd64PackedNumericSame32},
	"VCVTTPS2UDQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 32, truncate: true, explicit: "sae", shapes: amd64PackedNumericSame32},
	"VCVTUDQ2PS":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 32, explicit: "round", shapes: amd64PackedNumericSame32},
	"VCVTQQ2PD":    {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTUQQ2PD":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericSame64},
	"VCVTPS2QQ":    {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 32, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericWiden32To64},
	"VCVTPS2UQQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 64, explicit: "round", shapes: amd64PackedNumericWiden32To64},
	"VCVTTPS2QQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericSigned, sourceBits: 32, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericWiden32To64},
	"VCVTTPS2UQQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 32, destinationBits: 64, truncate: true, explicit: "sae", shapes: amd64PackedNumericWiden32To64},
	"VCVTUDQ2PD":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 64, shapes: amd64PackedNumericWiden32To64},
	"VCVTPD2UDQX":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTPD2UDQY":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTPD2UDQ":   {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTTPD2UDQX": {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTTPD2UDQY": {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTTPD2UDQ":  {sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericUnsigned, sourceBits: 64, destinationBits: 32, truncate: true, explicit: "sae", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTQQ2PSX":   {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTQQ2PSY":   {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTQQ2PS":    {sourceKind: amd64PackedNumericSigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
	"VCVTUQQ2PSX":  {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}},
	"VCVTUQQ2PSY":  {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}},
	"VCVTUQQ2PS":   {sourceKind: amd64PackedNumericUnsigned, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32, explicit: "round", shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}},
}

type amd64PackedNumericForm struct {
	properties  amd64BinaryFloatingSuffix
	shape       amd64PackedNumericShape
	source      Operand
	destination Operand
	mask        string
}

func (c *amd64Ctx) lowerPackedNumericConversion(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedNumericConversionSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	form, err := c.parsePackedNumericConversionForm(baseOp, suffix, spec, ins)
	if err != nil {
		return true, false, err
	}
	source, err := c.loadPackedNumericConversionSource(spec, form)
	if err != nil {
		return true, false, err
	}
	computed := c.emitPackedNumericConversion(spec, form.shape.lanes, source, form.properties.rounding)
	if form.mask != "" {
		oldBytes, loadErr := c.loadPackedCompareBytes(form.destination, form.shape.destinationBytes)
		if loadErr != nil {
			return true, false, loadErr
		}
		physicalLanes := form.shape.destinationBytes * 8 / spec.destinationBits
		old := c.bitcastVectorBytesToIntegerLanes(form.shape.destinationBytes, physicalLanes, spec.destinationBits, oldBytes)
		if physicalLanes != form.shape.lanes {
			old = c.lowIntegerLanes(old, physicalLanes, form.shape.lanes, spec.destinationBits)
		}
		computed = amd64ApplyIntegerLaneMask(c, form.shape.lanes, spec.destinationBits, computed, old, form.mask, form.properties.zeroing)
	}
	return true, false, c.storePackedNumericConversionResult(form.destination.Reg, form.shape.destinationBytes, form.shape.lanes, spec.destinationBits, computed)
}

func (c *amd64Ctx) parsePackedNumericConversionForm(baseOp, suffix string, spec amd64PackedNumericConversionSpec, ins Instr) (amd64PackedNumericForm, error) {
	var form amd64PackedNumericForm
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix {
		return form, fmt.Errorf("%s %s has a suffix absent from Go 1.27's packed conversion optabs: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.rounding != "" && spec.explicit != "round" {
		return form, fmt.Errorf("%s %s does not enable explicit rounding: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae && spec.explicit != "sae" {
		return form, fmt.Errorf("%s %s does not enable SAE: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return form, fmt.Errorf("%s %s expects source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if properties.zeroing && !masked {
		return form, fmt.Errorf("%s %s zeroing requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return form, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return form, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	destinationBytes := amd64VectorByteWidth(destination.Reg)
	var shape amd64PackedNumericShape
	shapeFound := false
	for _, candidate := range spec.shapes {
		if candidate.destinationBytes == destinationBytes {
			shape, shapeFound = candidate, true
			break
		}
	}
	if !shapeFound || !c.isGoEVEXVectorRegister(destination, destinationBytes) {
		return form, fmt.Errorf("%s %s destination does not match its typed width shapes: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return form, fmt.Errorf("%s %s.BCST requires scalar memory: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, shape.sourceBytes) {
			return form, fmt.Errorf("%s %s source register does not match its typed width shape: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return form, fmt.Errorf("%s %s source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	explicit := properties.rounding != "" || properties.sae
	if explicit && (source.Kind != OpReg || shape != spec.shapes[len(spec.shapes)-1]) {
		return form, fmt.Errorf("%s %s explicit rounding/SAE requires its maximum-width register form: %q", c.goarch, baseOp, ins.Raw)
	}
	mask := ""
	if masked {
		loadedMask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return form, err
		}
		mask = loadedMask
	}
	return amd64PackedNumericForm{properties: properties, shape: shape, source: source, destination: destination, mask: mask}, nil
}

func (c *amd64Ctx) loadPackedNumericConversionSource(spec amd64PackedNumericConversionSpec, form amd64PackedNumericForm) (string, error) {
	if form.properties.broadcast {
		value, err := c.evalIntSized(form.source, amd64IntegerTypeForBits(spec.sourceBits))
		if err != nil {
			return "", err
		}
		return amd64SplatInteger(c, form.shape.lanes, spec.sourceBits, value), nil
	}
	return c.loadPackedExtendInputs(form.source, form.shape.sourceBytes, form.shape.lanes, spec.sourceBits)
}

func (c *amd64Ctx) emitPackedNumericConversion(spec amd64PackedNumericConversionSpec, lanes int, source, rounding string) string {
	if spec.destinationKind == amd64PackedNumericFloat {
		return c.emitPackedIntegerToFloating(spec, lanes, source, rounding)
	}
	return c.emitPackedFloatingToInteger(spec, lanes, source, rounding)
}

func (c *amd64Ctx) emitPackedIntegerToFloating(spec amd64PackedNumericConversionSpec, lanes int, source, rounding string) string {
	sourceType := fmt.Sprintf("<%d x i%d>", lanes, spec.sourceBits)
	roundingMode := c.packedNumericRoundingMode(rounding)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		value, inserted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", value, sourceType, source, lane)
		bits := c.emitPackedIntegerToFloatingLane(spec, "%"+value, roundingMode)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, lanes, spec.destinationBits, result, spec.destinationBits, bits, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) packedNumericRoundingMode(rounding string) string {
	switch rounding {
	case "RN_SAE":
		return "0"
	case "RD_SAE":
		return "1"
	case "RU_SAE":
		return "2"
	case "RZ_SAE":
		return "3"
	default:
		mxcsr := c.loadMXCSR()
		shifted, mode := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i32 %s, 13\n", shifted, mxcsr)
		fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 3\n", mode, shifted)
		return "%" + mode
	}
}

// emitPackedIntegerToFloatingLane constructs IEEE-754 bits directly. LLVM 22
// lowers constrained integer-to-floating conversions to instructions that use
// MXCSR even when fixed rounding metadata is present, so relying on those
// intrinsics would silently miscompile EVEX {rn,rd,ru,rz}-sae forms.
func (c *amd64Ctx) emitPackedIntegerToFloatingLane(spec amd64PackedNumericConversionSpec, value, roundingMode string) string {
	negative := "false"
	magnitudeSource := value
	if spec.sourceKind == amd64PackedNumericSigned {
		isNegative, negated, magnitude := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %s, 0\n", isNegative, spec.sourceBits, value)
		fmt.Fprintf(c.b, "  %%%s = sub i%d 0, %s\n", negated, spec.sourceBits, value)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %s\n", magnitude, isNegative, spec.sourceBits, negated, spec.sourceBits, value)
		negative = "%" + isNegative
		magnitudeSource = "%" + magnitude
	}
	magnitude := magnitudeSource
	if spec.sourceBits != 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", wide, spec.sourceBits, magnitudeSource)
		magnitude = "%" + wide
	}

	zero, leadingZeros, highest := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %s, 0\n", zero, magnitude)
	fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.ctlz.i64(i64 %s, i1 false)\n", leadingZeros, magnitude)
	fmt.Fprintf(c.b, "  %%%s = sub i64 63, %%%s\n", highest, leadingZeros)

	mantissaBits := 23
	bias := 127
	if spec.destinationBits == 64 {
		mantissaBits = 52
		bias = 1023
	}
	needsRound, rightShiftRaw, safeRightShift := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i64 %%%s, %d\n", needsRound, highest, mantissaBits)
	fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, %d\n", rightShiftRaw, highest, mantissaBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 0\n", safeRightShift, needsRound, rightShiftRaw)
	leftShiftRaw, safeLeftShift := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %d, %%%s\n", leftShiftRaw, mantissaBits, highest)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %%%s\n", safeLeftShift, needsRound, leftShiftRaw)
	shiftedRight, shiftedLeft, unrounded := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %%%s\n", shiftedRight, magnitude, safeRightShift)
	fmt.Fprintf(c.b, "  %%%s = shl i64 %s, %%%s\n", shiftedLeft, magnitude, safeLeftShift)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", unrounded, needsRound, shiftedRight, shiftedLeft)

	oneShifted, remainderMask, remainder, remainderPresent := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl i64 1, %%%s\n", oneShifted, safeRightShift)
	fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", remainderMask, oneShifted)
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %%%s\n", remainder, magnitude, remainderMask)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", remainderPresent, remainder)
	nonzero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", nonzero, needsRound, remainderPresent)
	halfShiftRaw, safeHalfShift, half := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub i64 %%%s, 1\n", halfShiftRaw, safeRightShift)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 0\n", safeHalfShift, needsRound, halfShiftRaw)
	fmt.Fprintf(c.b, "  %%%s = shl i64 1, %%%s\n", half, safeHalfShift)
	aboveHalf, equalHalf, lowBit, odd, tiedOdd := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ugt i64 %%%s, %%%s\n", aboveHalf, remainder, half)
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, %%%s\n", equalHalf, remainder, half)
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", lowBit, unrounded)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", odd, lowBit)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tiedOdd, equalHalf, odd)
	nearestRaw, nearest := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", nearestRaw, aboveHalf, tiedOdd)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", nearest, needsRound, nearestRaw)
	increment := c.emitScaledRoundIncrement(roundingMode, negative, "%"+nonzero, "%"+nearest)
	increment64, rounded := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %s to i64\n", increment64, increment)
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", rounded, unrounded, increment64)

	carryThreshold := uint64(1) << (mantissaBits + 1)
	carry, carried, significand := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i64 %%%s, %d\n", carry, rounded, carryThreshold)
	fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, 1\n", carried, rounded)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %%%s, i64 %%%s\n", significand, carry, carried, rounded)
	carry64, effectiveHighest, biasedExponent, exponentBits := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", carry64, carry)
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %%%s\n", effectiveHighest, highest, carry64)
	fmt.Fprintf(c.b, "  %%%s = add i64 %%%s, %d\n", biasedExponent, effectiveHighest, bias)
	fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %d\n", exponentBits, biasedExponent, mantissaBits)
	mantissaMask := (uint64(1) << mantissaBits) - 1
	fraction, magnitudeBits := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, %d\n", fraction, significand, mantissaMask)
	fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", magnitudeBits, exponentBits, fraction)
	assembled := "%" + magnitudeBits
	if spec.sourceKind == amd64PackedNumericSigned {
		signBits, signedBits := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %d, i64 0\n", signBits, negative, uint64(1)<<(spec.destinationBits-1))
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", signedBits, magnitudeBits, signBits)
		assembled = "%" + signedBits
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 0, i64 %s\n", selected, zero, assembled)
	if spec.destinationBits == 64 {
		return "%" + selected
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", result, selected)
	return "%" + result
}

func (c *amd64Ctx) emitPackedFloatingToInteger(spec amd64PackedNumericConversionSpec, lanes int, source, rounding string) string {
	sourceIntegerType := fmt.Sprintf("<%d x i%d>", lanes, spec.sourceBits)
	sourceFloatType := amd64FloatingVectorType(lanes, spec.sourceBits)
	floating := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", floating, sourceIntegerType, source, sourceFloatType)
	result := "poison"
	floatType := amd64FloatingScalarType(spec.sourceBits)
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", value, sourceFloatType, floating, lane)
		rounded := c.emitPackedNumericRoundedValue(floatType, spec.sourceBits, "%"+value, spec.truncate, rounding)
		conversion := "fptosi"
		if spec.destinationKind == amd64PackedNumericUnsigned {
			conversion = "fptoui"
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.%s.sat.i%d.f%d(%s %s)\n", converted, spec.destinationBits, conversion, spec.destinationBits, spec.sourceBits, floatType, rounded)
		valid := c.emitPackedNumericIntegerRangeCheck(spec, floatType, rounded)
		indefinite := uint64(1) << (spec.destinationBits - 1)
		if spec.destinationKind == amd64PackedNumericUnsigned {
			if spec.destinationBits == 64 {
				indefinite = ^uint64(0)
			} else {
				indefinite = (uint64(1) << spec.destinationBits) - 1
			}
		}
		selected, inserted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %d\n", selected, valid, spec.destinationBits, converted, spec.destinationBits, indefinite)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, spec.destinationBits, result, spec.destinationBits, selected, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) emitPackedNumericRoundedValue(floatType string, sourceBits int, value string, truncate bool, rounding string) string {
	intrinsic := "rint"
	switch {
	case truncate || rounding == "RZ_SAE":
		intrinsic = "trunc"
	case rounding == "RN_SAE":
		intrinsic = "roundeven"
	case rounding == "RD_SAE":
		intrinsic = "floor"
	case rounding == "RU_SAE":
		intrinsic = "ceil"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.f%d(%s %s)\n", result, floatType, intrinsic, sourceBits, floatType, value)
	return "%" + result
}

func (c *amd64Ctx) emitPackedNumericIntegerRangeCheck(spec amd64PackedNumericConversionSpec, floatType, rounded string) string {
	lowerBound, upperBound := "0.000000e+00", "4.294967296000000e+09"
	if spec.destinationBits == 64 {
		upperBound = "1.8446744073709552e+19"
	}
	if spec.destinationKind == amd64PackedNumericSigned {
		lowerBound, upperBound = "-2.147483648000000e+09", "2.147483648000000e+09"
		if spec.destinationBits == 64 {
			lowerBound, upperBound = "-9.2233720368547758e+18", "9.2233720368547758e+18"
		}
	}
	lower, upper, valid := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp oge %s %s, %s\n", lower, floatType, rounded, lowerBound)
	fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %s, %s\n", upper, floatType, rounded, upperBound)
	fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", valid, lower, upper)
	return "%" + valid
}

func (c *amd64Ctx) storePackedNumericConversionResult(destination Reg, destinationBytes, resultLanes, laneBits int, result string) error {
	physicalLanes := destinationBytes * 8 / laneBits
	if physicalLanes != resultLanes {
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> zeroinitializer, <%d x i32> <", widened, resultLanes, laneBits, result, resultLanes, laneBits, physicalLanes)
		for lane := 0; lane < physicalLanes; lane++ {
			if lane != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", lane)
		}
		c.b.WriteString(">\n")
		result = "%" + widened
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, physicalLanes, laneBits, result, destinationBytes)
	return c.storeVectorBytes(destination, destinationBytes, "%"+out)
}
