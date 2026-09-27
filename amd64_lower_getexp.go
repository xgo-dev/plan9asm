package plan9asm

import (
	"fmt"
	"strings"
)

type amd64GetExpSpec struct {
	laneBits int
	scalar   bool
}

var amd64GetExpSpecs = map[Op]amd64GetExpSpec{
	"VGETEXPPS": {laneBits: 32},
	"VGETEXPPD": {laneBits: 64},
	"VGETEXPSS": {laneBits: 32, scalar: true},
	"VGETEXPSD": {laneBits: 64, scalar: true},
}

func (c *amd64Ctx) lowerGetExp(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64GetExpSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's GETEXP optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar && properties.broadcast {
		return true, false, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	wantArgs := 2
	if spec.scalar {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs && len(ins.Args) != wantArgs+1 {
		return true, false, fmt.Errorf("%s %s has the wrong operand count for its packed/scalar grammar: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == wantArgs+1
	if c.goarch == "386" && spec.scalar && masked {
		return true, false, fmt.Errorf("386 %s mask form exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	maskIndex := len(ins.Args) - 2
	if masked && !amd64NonzeroKOperand(ins.Args[maskIndex]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if spec.scalar {
		if byteWidth != 16 || !c.isGoEVEXVectorRegister(destination, 16) || !c.isGoEVEXVectorRegister(ins.Args[1], 16) {
			return true, false, fmt.Errorf("%s %s scalar pass-through and destination must be X registers: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s packed destination must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("%s %s source register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae {
		if source.Kind != OpReg || !spec.scalar && byteWidth != 64 {
			return true, false, fmt.Errorf("%s %s.SAE requires a register source and scalar or Z form: %q", c.goarch, baseOp, ins.Raw)
		}
	}

	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[maskIndex].Reg)
		if err != nil {
			return true, false, err
		}
	}
	daz := c.loadMXCSRDAZ()
	if spec.scalar {
		return c.lowerScalarGetExp(spec, properties, source, ins.Args[1], destination, mask, daz)
	}
	return c.lowerPackedGetExp(spec, properties, source, destination, byteWidth, mask, daz)
}

func (c *amd64Ctx) lowerPackedGetExp(spec amd64GetExpSpec, properties amd64BinaryFloatingSuffix, source, destination Operand, byteWidth int, mask, daz string) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	input, err := c.loadPackedCompareLanes(source, byteWidth, spec.laneBits, properties.broadcast)
	if err != nil {
		return true, false, err
	}
	result := c.emitGetExpBits(lanes, spec.laneBits, input, daz)
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

func (c *amd64Ctx) lowerScalarGetExp(spec amd64GetExpSpec, properties amd64BinaryFloatingSuffix, source, passthrough, destination Operand, mask, daz string) (bool, bool, error) {
	sourceBits, err := c.loadFloatingScalarBits(source, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", input, spec.laneBits, spec.laneBits, sourceBits)
	result := c.emitGetExpBits(1, spec.laneBits, "%"+input, daz)
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i%d> %s, i32 0\n", low, spec.laneBits, result)
	passthroughBytes, err := c.loadX(passthrough.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, passthroughBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+low, base, mask, properties.zeroing)
}

func (c *amd64Ctx) emitGetExpBits(lanes, laneBits int, input, daz string) string {
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	floatType := amd64FloatingScalarType(laneBits)
	mantissaBits, bias, denormalOffset := 23, 127, 149
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	signBit := uint64(0x80000000)
	if laneBits == 64 {
		mantissaBits, bias, denormalOffset = 52, 1023, 1074
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
		signBit = uint64(0x8000000000000000)
	}
	positiveInfinity := exponentMask
	negativeInfinity := signBit | exponentMask
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		bits, exponent, mantissa := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", bits, vectorType, input, lane)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", exponent, laneBits, bits, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = and i%d %%%s, %d\n", mantissa, laneBits, bits, mantissaMask)
		exponentZero, exponentOnes := c.newTmp(), c.newTmp()
		mantissaZero, mantissaNonzero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", exponentZero, laneBits, exponent)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, %d\n", exponentOnes, laneBits, exponent, exponentMask)
		fmt.Fprintf(c.b, "  %%%s = icmp eq i%d %%%s, 0\n", mantissaZero, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i%d %%%s, 0\n", mantissaNonzero, laneBits, mantissa)
		isNaN, isInfinity, isDenormal := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isNaN, exponentOnes, mantissaNonzero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isInfinity, exponentOnes, mantissaZero)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isDenormal, exponentZero, mantissaNonzero)
		zeroOrDAZ, isEffectiveZero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %s\n", zeroOrDAZ, mantissaZero, daz)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", isEffectiveZero, exponentZero, zeroOrDAZ)

		normalField, normalExponent := c.newTmp(), c.newTmp()
		leadingZeros, highestBit, denormalExponent := c.newTmp(), c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr i%d %%%s, %d\n", normalField, laneBits, exponent, mantissaBits)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, %d\n", normalExponent, laneBits, normalField, bias)
		fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.ctlz.i%d(i%d %%%s, i1 false)\n", leadingZeros, laneBits, laneBits, laneBits, mantissa)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %d, %%%s\n", highestBit, laneBits, laneBits-1, leadingZeros)
		fmt.Fprintf(c.b, "  %%%s = sub i%d %%%s, %d\n", denormalExponent, laneBits, highestBit, denormalOffset)
		exponentValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", exponentValue, isDenormal, laneBits, denormalExponent, laneBits, normalExponent)
		exponentFloat, exponentBits := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sitofp i%d %%%s to %s\n", exponentFloat, laneBits, exponentValue, floatType)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to i%d\n", exponentBits, floatType, exponentFloat, laneBits)
		withInfinity, withZero := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %%%s\n", withInfinity, isInfinity, laneBits, positiveInfinity, laneBits, exponentBits)
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %d, i%d %%%s\n", withZero, isEffectiveZero, laneBits, negativeInfinity, laneBits, withInfinity)
		quietNaN := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i%d %%%s, %d\n", quietNaN, laneBits, bits, quietBit)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i%d %%%s, i%d %%%s\n", selected, isNaN, laneBits, quietNaN, laneBits, withZero)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, vectorType, result, laneBits, selected, lane)
		result = "%" + inserted
	}
	return result
}
