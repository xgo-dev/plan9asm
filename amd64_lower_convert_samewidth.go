package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SameWidthConversionMode uint8

const (
	amd64SameWidthIntToFloat amd64SameWidthConversionMode = iota
	amd64SameWidthFloatToInt
	amd64SameWidthFloatToIntTruncate
	amd64SameWidthSqrt
)

type amd64SameWidthConversionSpec struct {
	laneBits int
	mode     amd64SameWidthConversionMode
	sae      bool
	rawOnly  bool
}

var amd64SameWidthConversionSpecs = map[Op]amd64SameWidthConversionSpec{
	"VCVTDQ2PS":  {laneBits: 32, mode: amd64SameWidthIntToFloat},
	"VCVTPS2DQ":  {laneBits: 32, mode: amd64SameWidthFloatToInt},
	"VCVTTPS2DQ": {laneBits: 32, mode: amd64SameWidthFloatToIntTruncate, sae: true},
	"VSQRTPD":    {laneBits: 64, mode: amd64SameWidthSqrt},
	"VSQRTPS":    {laneBits: 32, mode: amd64SameWidthSqrt},
	"VSQRTPH":    {laneBits: 16, mode: amd64SameWidthSqrt, rawOnly: true},
}

// lowerSameWidthPackedConversion implements all five opcodes sharing Go
// 1.27's _yvcvtdq2ps table. Although the table is shared, VCVTTPS2DQ enables
// SAE while the other four opcodes enable explicit rounding on Z forms.
func (c *amd64Ctx) lowerSameWidthPackedConversion(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64SameWidthConversionSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.rawOnly && !ins.x86Encoded {
		return true, false, fmt.Errorf("%s is absent from Go's named assembler table; raw encoding required", baseOp)
	}

	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvcvtdq2ps encodings: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.sae {
		if properties.rounding != "" {
			return true, false, fmt.Errorf("%s %s supports SAE, not explicit rounding: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if properties.sae {
		return true, false, fmt.Errorf("%s %s supports explicit rounding, not SAE: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector-register class: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	explicitControl := properties.rounding != "" || properties.sae
	if explicitControl && (byteWidth != 64 || source.Kind != OpReg) {
		return true, false, fmt.Errorf("%s %s explicit rounding/SAE requires a Z register source: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("%s %s source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth * 8 / spec.laneBits
	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
	}
	sourceBits, err := c.loadMaskedPackedCompareLanes(source, byteWidth, spec.laneBits, properties.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	computedBits := c.emitSameWidthPackedConversion(spec, sourceBits, byteWidth, properties)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		computedBits = amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computedBits, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, spec.laneBits, computedBits, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

func (c *amd64Ctx) emitSameWidthPackedConversion(spec amd64SameWidthConversionSpec, sourceBits string, byteWidth int, properties amd64BinaryFloatingSuffix) string {
	lanes := byteWidth * 8 / spec.laneBits
	integerType := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	floatType := amd64FMA3LLVMType(lanes, spec.laneBits)
	switch spec.mode {
	case amd64SameWidthIntToFloat:
		converted := c.newTmp()
		if properties.rounding != "" {
			fmt.Fprintf(c.b, "  %%%s = call <16 x float> @llvm.experimental.constrained.sitofp.v16f32.v16i32(<16 x i32> %s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", converted, sourceBits, amd64FMA3RoundingMetadata(properties.rounding))
		} else {
			fmt.Fprintf(c.b, "  %%%s = sitofp %s %s to %s\n", converted, integerType, sourceBits, floatType)
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", bits, floatType, converted, integerType)
		return "%" + bits

	case amd64SameWidthFloatToInt, amd64SameWidthFloatToIntTruncate:
		floating := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", floating, integerType, sourceBits, floatType)
		truncate := spec.mode == amd64SameWidthFloatToIntTruncate
		return c.emitPackedFloatToDword("%"+floating, lanes, truncate, properties.rounding)

	case amd64SameWidthSqrt:
		floating := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to %s\n", floating, integerType, sourceBits, floatType)
		computed := c.newTmp()
		if properties.rounding != "" {
			name := fmt.Sprintf("llvm.experimental.constrained.sqrt.v%df%d", lanes, spec.laneBits)
			fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %%%s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", computed, floatType, name, floatType, floating, amd64FMA3RoundingMetadata(properties.rounding))
		} else {
			name := fmt.Sprintf("llvm.sqrt.v%df%d", lanes, spec.laneBits)
			fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %%%s)\n", computed, floatType, name, floatType, floating)
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", bits, floatType, computed, integerType)
		return "%" + bits
	}
	panic("unreachable same-width packed conversion mode")
}

func (c *amd64Ctx) emitPackedFloatToDword(floating string, lanes int, truncate bool, rounding string) string {
	// LLVM 22 cannot legalize the chain-bearing AVX conversion intrinsics when
	// a generic target has no AVX feature attribute. Scalarizing also avoids
	// its LOOP_DEPENDENCE_MASK crash for constrained vector rounding on i386.
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x float> %s, i32 %d\n", value, lanes, floating, lane)
		rounded := c.newTmp()
		switch {
		case truncate:
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.trunc.f32(float %%%s)\n", rounded, value)
		case rounding == "RN_SAE":
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.floor.f32(float %%%s)\n", rounded, value)
			fraction := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fsub float %%%s, %%%s\n", fraction, value, rounded)
			aboveHalf := c.newTmp()
			equalHalf := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fcmp ogt float %%%s, 5.000000e-01\n", aboveHalf, fraction)
			fmt.Fprintf(c.b, "  %%%s = fcmp oeq float %%%s, 5.000000e-01\n", equalHalf, fraction)
			floorInt := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fptosi.sat.i32.f32(float %%%s)\n", floorInt, rounded)
			floorLowBit := c.newTmp()
			floorOdd := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i32 %%%s, 1\n", floorLowBit, floorInt)
			fmt.Fprintf(c.b, "  %%%s = icmp ne i32 %%%s, 0\n", floorOdd, floorLowBit)
			tieRoundsUp := c.newTmp()
			roundUp := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", tieRoundsUp, equalHalf, floorOdd)
			fmt.Fprintf(c.b, "  %%%s = or i1 %%%s, %%%s\n", roundUp, aboveHalf, tieRoundsUp)
			ceiling := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fadd float %%%s, 1.000000e+00\n", ceiling, rounded)
			roundEven := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, float %%%s, float %%%s\n", roundEven, roundUp, ceiling, rounded)
			rounded = roundEven
		case rounding == "RD_SAE":
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.floor.f32(float %%%s)\n", rounded, value)
		case rounding == "RU_SAE":
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.ceil.f32(float %%%s)\n", rounded, value)
		case rounding == "RZ_SAE":
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.trunc.f32(float %%%s)\n", rounded, value)
		default:
			fmt.Fprintf(c.b, "  %%%s = call float @llvm.rint.f32(float %%%s)\n", rounded, value)
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fptosi.sat.i32.f32(float %%%s)\n", converted, rounded)
		lower := c.newTmp()
		upper := c.newTmp()
		valid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oge float %%%s, -2.147483648000000e+09\n", lower, rounded)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt float %%%s, 2.147483648000000e+09\n", upper, rounded)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", valid, lower, upper)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 -2147483648\n", selected, valid, converted)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %%%s, i32 %d\n", inserted, lanes, result, selected, lane)
		result = "%" + inserted
	}
	return result
}
