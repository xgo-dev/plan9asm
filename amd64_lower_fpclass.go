package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FPClassSpec struct {
	laneBits int
	bytes    int
	scalar   bool
}

// amd64FPClassSpecs mirrors the width-specialized opcode names in Go 1.27's
// _yvfpclasspdx/_yvfpclasspdy/_yvfpclasspdz tables. Classification itself is
// shared across every packed and scalar form.
var amd64FPClassSpecs = map[Op]amd64FPClassSpec{
	"VFPCLASSPDX": {laneBits: 64, bytes: 16},
	"VFPCLASSPDY": {laneBits: 64, bytes: 32},
	"VFPCLASSPDZ": {laneBits: 64, bytes: 64},
	"VFPCLASSPSX": {laneBits: 32, bytes: 16},
	"VFPCLASSPSY": {laneBits: 32, bytes: 32},
	"VFPCLASSPSZ": {laneBits: 32, bytes: 64},
	"VFPCLASSSD":  {laneBits: 64, bytes: 16, scalar: true},
	"VFPCLASSSS":  {laneBits: 32, bytes: 16, scalar: true},
}

func (c *amd64Ctx) lowerFPClass(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FPClassSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	broadcast := suffix == "BCST"
	if suffix != "" && !broadcast {
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's FPCLASS optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar && broadcast {
		return true, false, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects immediate, source, [K mask,] K destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s immediate must be an unsigned byte: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s input mask must be K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if !amd64IsKOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[1]
	if broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, spec.bytes) {
			return true, false, fmt.Errorf("%s %s source register does not match its opcode width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be its named vector width or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := spec.bytes * 8 / spec.laneBits
	var bits string
	if spec.scalar {
		scalarBits, loadErr := c.loadFloatingScalarBits(source, spec.laneBits)
		if loadErr != nil {
			return true, false, loadErr
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i%d> poison, i%d %s, i32 0\n", inserted, spec.laneBits, spec.laneBits, scalarBits)
		bits = "%" + inserted
		lanes = 1
	} else {
		bits, err = c.loadPackedCompareLanes(source, spec.bytes, spec.laneBits, broadcast)
		if err != nil {
			return true, false, err
		}
	}
	classified := c.emitFPClassPredicate(lanes, spec.laneBits, bits, uint8(ins.Args[0].Imm))
	var result string
	if lanes == 1 {
		low := c.newTmp()
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i1> %s, i32 0\n", low, classified)
		fmt.Fprintf(c.b, "  %%%s = zext i1 %%%s to i64\n", wide, low)
		result = "%" + wide
	} else {
		result = c.packFloatingCompareMask(classified, lanes)
	}
	if masked {
		writeMask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		maskedResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", maskedResult, result, writeMask)
		result = "%" + maskedResult
	}
	return true, false, c.storeK(destination.Reg, result)
}

func (c *amd64Ctx) emitFPClassPredicate(lanes, laneBits int, bits string, immediate uint8) string {
	integerType := fmt.Sprintf("<%d x i%d>", lanes, laneBits)
	predicateType := fmt.Sprintf("<%d x i1>", lanes)
	exponentMask := uint64(0x7f800000)
	mantissaMask := uint64(0x007fffff)
	quietBit := uint64(0x00400000)
	if laneBits == 64 {
		exponentMask = uint64(0x7ff0000000000000)
		mantissaMask = uint64(0x000fffffffffffff)
		quietBit = uint64(0x0008000000000000)
	}
	exponent, mantissa, quiet := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", exponent, integerType, bits, llvmSplatInteger(lanes, laneBits, exponentMask))
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", mantissa, integerType, bits, llvmSplatInteger(lanes, laneBits, mantissaMask))
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", quiet, integerType, bits, llvmSplatInteger(lanes, laneBits, quietBit))
	exponentOnes, exponentNotOnes := c.newTmp(), c.newTmp()
	exponentZero, exponentNotZero := c.newTmp(), c.newTmp()
	mantissaZero, mantissaNonzero := c.newTmp(), c.newTmp()
	quietSet, quietClear := c.newTmp(), c.newTmp()
	negative, nonnegative := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, %s\n", exponentOnes, integerType, exponent, llvmSplatInteger(lanes, laneBits, exponentMask))
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, %s\n", exponentNotOnes, integerType, exponent, llvmSplatInteger(lanes, laneBits, exponentMask))
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", exponentZero, integerType, exponent)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", exponentNotZero, integerType, exponent)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", mantissaZero, integerType, mantissa)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", mantissaNonzero, integerType, mantissa)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", quietSet, integerType, quiet)
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, zeroinitializer\n", quietClear, integerType, quiet)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, zeroinitializer\n", negative, integerType, bits)
	fmt.Fprintf(c.b, "  %%%s = icmp sge %s %s, zeroinitializer\n", nonnegative, integerType, bits)
	daz := c.loadMXCSRDAZ()
	dazClear := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq i1 %s, false\n", dazClear, daz)
	dazSetVector := amd64SplatI1(c, lanes, daz)
	dazClearVector := amd64SplatI1(c, lanes, "%"+dazClear)
	and := func(first, second string) string {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", value, predicateType, first, second)
		return "%" + value
	}
	categories := [8]string{}
	nan := and("%"+exponentOnes, "%"+mantissaNonzero)
	categories[0] = and(nan, "%"+quietSet)
	effectiveMantissaZero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", effectiveMantissaZero, predicateType, mantissaZero, dazSetVector)
	zero := and("%"+exponentZero, "%"+effectiveMantissaZero)
	categories[1] = and(zero, "%"+nonnegative)
	categories[2] = and(zero, "%"+negative)
	infinity := and("%"+exponentOnes, "%"+mantissaZero)
	categories[3] = and(infinity, "%"+nonnegative)
	categories[4] = and(infinity, "%"+negative)
	effectiveMantissaNonzero := and("%"+mantissaNonzero, dazClearVector)
	categories[5] = and("%"+exponentZero, effectiveMantissaNonzero)
	negativeFinite := and("%"+negative, "%"+exponentNotOnes)
	effectiveNonzero := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = or %s %%%s, %s\n", effectiveNonzero, predicateType, exponentNotZero, effectiveMantissaNonzero)
	categories[6] = and(negativeFinite, "%"+effectiveNonzero)
	categories[7] = and(nan, "%"+quietClear)
	result := "zeroinitializer"
	for category, predicate := range categories {
		if immediate&(1<<category) == 0 {
			continue
		}
		if result == "zeroinitializer" {
			result = predicate
			continue
		}
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %s\n", combined, predicateType, result, predicate)
		result = "%" + combined
	}
	return result
}

func (c *amd64Ctx) loadMXCSRDAZ() string {
	mxcsr := c.loadMXCSR()
	dazBits := c.newTmp()
	daz := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i32 %s, 64\n", dazBits, mxcsr)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", daz, dazBits)
	return "%" + daz
}

func (c *amd64Ctx) loadMXCSR() string {
	mxcsrSlot, mxcsr := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = alloca i32\n", mxcsrSlot)
	fmt.Fprintf(c.b, "  call void @llvm.x86.sse.stmxcsr(ptr %%%s)\n", mxcsrSlot)
	fmt.Fprintf(c.b, "  %%%s = load i32, ptr %%%s\n", mxcsr, mxcsrSlot)
	return "%" + mxcsr
}
