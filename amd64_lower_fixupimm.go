package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FixupImmediateSpec struct {
	laneBits int
	scalar   bool
}

var amd64FixupImmediateSpecs = map[Op]amd64FixupImmediateSpec{
	"VFIXUPIMMPS": {laneBits: 32},
	"VFIXUPIMMPD": {laneBits: 64},
	"VFIXUPIMMSS": {laneBits: 32, scalar: true},
	"VFIXUPIMMSD": {laneBits: 64, scalar: true},
}

func (c *amd64Ctx) lowerFixupImmediate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FixupImmediateSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	shape := amd64UnaryImmediateFloatingShape{laneBits: spec.laneBits, scalar: spec.scalar, twoSource: true}
	form, err := c.parseUnaryImmediateFloatingForm(baseOp, suffix, shape, ins)
	if err != nil {
		return true, false, err
	}
	daz := c.loadMXCSRDAZ()
	if spec.scalar {
		return c.lowerScalarFixupImmediate(spec, form, daz)
	}
	return c.lowerPackedFixupImmediate(spec, form, daz)
}

func (c *amd64Ctx) lowerPackedFixupImmediate(spec amd64FixupImmediateSpec, form amd64UnaryImmediateFloatingForm, daz string) (bool, bool, error) {
	lanes := form.byteWidth * 8 / spec.laneBits
	table, err := c.loadPackedCompareLanes(form.source, form.byteWidth, spec.laneBits, form.properties.broadcast)
	if err != nil {
		return true, false, err
	}
	classified, err := c.loadPackedCompareLanes(form.passthrough, form.byteWidth, spec.laneBits, false)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(form.destination, form.byteWidth)
	if err != nil {
		return true, false, err
	}
	old := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, spec.laneBits, oldBytes)
	result := c.emitFixupImmediateBits(lanes, spec.laneBits, classified, table, old, daz)
	if form.mask != "" {
		result = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, result, old, form.mask, form.properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, result, form.byteWidth)
	return true, false, c.storeVectorBytes(form.destination.Reg, form.byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarFixupImmediate(spec amd64FixupImmediateSpec, form amd64UnaryImmediateFloatingForm, daz string) (bool, bool, error) {
	tableBits, err := c.loadFloatingScalarBits(form.source, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	classifiedBytes, err := c.loadX(form.passthrough.Reg)
	if err != nil {
		return true, false, err
	}
	classifiedVector := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, classifiedBytes)
	classifiedLow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 0\n", classifiedLow, 128/spec.laneBits, spec.laneBits, classifiedVector)
	oldLow, err := c.loadXLowInteger(form.destination.Reg, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	tableVector, classifiedOne, oldVector := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", tableVector, spec.laneBits, spec.laneBits, tableBits)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %%%s, i32 0\n", classifiedOne, spec.laneBits, spec.laneBits, classifiedLow)
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", oldVector, spec.laneBits, spec.laneBits, oldLow)
	result := c.emitFixupImmediateBits(1, spec.laneBits, "%"+classifiedOne, "%"+tableVector, "%"+oldVector, daz)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	return true, false, c.storeVectorScalarRegister(form.destination.Reg, spec.laneBits, "%"+low, classifiedVector, form.mask, form.properties.zeroing)
}

// emitFixupImmediateBits implements the data-result portion of Intel's
// FIXUPIMM_SP/FIXUPIMM_DP grammar. imm8 controls only MXCSR exception
// reporting; plan9asm does not currently expose floating exception state.
func (c *amd64Ctx) emitFixupImmediateBits(lanes, laneBits int, classified, table, old, daz string) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	signBit := uint64(0x80000000)
	positiveOne := uint64(0x3f800000)
	constants := [16]uint64{
		0, 0, 0, 0xffc00000,
		0xff800000, 0x7f800000, 0, 0x80000000,
		0, 0xbf800000, 0x3f800000, 0x3f000000,
		0x42b40000, 0x3fc90fdb, 0x7f7fffff, 0xff7fffff,
	}
	if laneBits == 64 {
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
		signBit = uint64(0x8000000000000000)
		positiveOne = uint64(0x3ff0000000000000)
		constants = [16]uint64{
			0, 0, 0, 0xfff8000000000000,
			0xfff0000000000000, 0x7ff0000000000000, 0, 0x8000000000000000,
			0, 0xbff0000000000000, 0x3ff0000000000000, 0x3fe0000000000000,
			0x4056800000000000, 0x3ff921fb54442d18, 0x7fefffffffffffff, 0xffefffffffffffff,
		}
	}
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		raw, tableLane, oldLane := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", raw, vectorType, classified, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", tableLane, vectorType, table, lane)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", oldLane, vectorType, old, lane)
		rawExponent, exponentZero, dazZero := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", rawExponent, laneBits, raw, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", exponentZero, laneBits, rawExponent)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %s\n", dazZero, exponentZero, daz)
		effective := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 0, i%d %%%s\n", effective, dazZero, laneBits, laneBits, raw)

		exponent, mantissa, sign, absolute := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", exponent, laneBits, effective, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", mantissa, laneBits, effective, mantissaMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", sign, laneBits, effective, signBit)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", absolute, laneBits, effective, signBit-1)
		exponentOnes, mantissaZero, mantissaNonzero, negative, zero := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", exponentOnes, laneBits, exponent, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", mantissaZero, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", mantissaNonzero, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", negative, laneBits, sign)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", zero, laneBits, absolute)
		isNaN, isInfinity, quietSet := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isNaN, exponentOnes, mantissaNonzero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isInfinity, exponentOnes, mantissaZero)
		quietValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", quietValue, laneBits, mantissa, quietBit)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", quietSet, laneBits, quietValue)
		notQuiet, signalingNaN, quietNaN := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notQuiet, quietSet)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", signalingNaN, isNaN, notQuiet)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", quietNaN, isNaN, quietSet)
		negativeInfinity, positiveInfinity, notNegative := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", negativeInfinity, isInfinity, negative)
		fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", notNegative, negative)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", positiveInfinity, isInfinity, notNegative)
		positiveOneValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", positiveOneValue, laneBits, effective, positiveOne)

		token := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d 6, i%d 7\n", token, negative, laneBits, laneBits)
		for _, selection := range []struct {
			predicate string
			value     int
		}{
			{predicate: positiveInfinity, value: 5},
			{predicate: negativeInfinity, value: 4},
			{predicate: positiveOneValue, value: 3},
			{predicate: zero, value: 2},
			{predicate: signalingNaN, value: 1},
			{predicate: quietNaN, value: 0},
		} {
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %%%s\n", selected, selection.predicate, laneBits, selection.value, laneBits, token)
			token = selected
		}
		shift, shiftedTable, response := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl i%d %%%s, 2\n", shift, laneBits, token)
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %%%s\n", shiftedTable, laneBits, tableLane, shift)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, 15\n", response, laneBits, shiftedTable)

		quieted, signedInfinity := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", quieted, laneBits, effective, exponentMask|quietBit)
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", signedInfinity, laneBits, sign, exponentMask)
		responseValues := [16]string{
			"%" + oldLane, "%" + effective, "%" + quieted,
			fmt.Sprintf("%d", constants[3]), fmt.Sprintf("%d", constants[4]), fmt.Sprintf("%d", constants[5]), "%" + signedInfinity,
			fmt.Sprintf("%d", constants[7]), fmt.Sprintf("%d", constants[8]), fmt.Sprintf("%d", constants[9]), fmt.Sprintf("%d", constants[10]),
			fmt.Sprintf("%d", constants[11]), fmt.Sprintf("%d", constants[12]), fmt.Sprintf("%d", constants[13]), fmt.Sprintf("%d", constants[14]), fmt.Sprintf("%d", constants[15]),
		}
		laneResult := responseValues[0]
		for responseValue := 1; responseValue < len(responseValues); responseValue++ {
			matches, selected := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", matches, laneBits, response, responseValue)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %s, i%d %s\n", selected, matches, laneBits, responseValues[responseValue], laneBits, laneResult)
			laneResult = "%" + selected
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, result, laneBits, laneResult, lane)
		result = "%" + inserted
	}
	return result
}
