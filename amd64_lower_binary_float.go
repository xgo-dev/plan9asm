package plan9asm

import (
	"fmt"
	"strings"
)

type amd64BinaryFloatingMode uint8

const (
	amd64BinaryFloatingAdd amd64BinaryFloatingMode = iota
	amd64BinaryFloatingSub
	amd64BinaryFloatingMul
	amd64BinaryFloatingDiv
	amd64BinaryFloatingMax
	amd64BinaryFloatingMin
	amd64BinaryFloatingSqrt
	amd64BinaryFloatingScale
)

type amd64BinaryFloatingSpec struct {
	laneBits int
	mode     amd64BinaryFloatingMode
	scalar   bool
	sae      bool
	rawOnly  bool
}

// amd64BinaryFloatingSpecs covers Go 1.27's complete V-prefixed binary
// floating-point family and the raw-only AVX-512 FP16 packed/scalar binary family.
// Packed Go forms use _yvaddpd, while scalar Go forms and VSQRTSS/VSQRTSD
// use _yvaddsd. SCALEF uses the same source/destination shape through
// _yvscalefpd/_yvgetexpsd. MAX/MIN enable SAE; arithmetic, square-root, and
// scale operations enable explicit rounding.
var amd64BinaryFloatingSpecs = map[Op]amd64BinaryFloatingSpec{
	"VADDPH":    {laneBits: 16, mode: amd64BinaryFloatingAdd, rawOnly: true},
	"VSUBPH":    {laneBits: 16, mode: amd64BinaryFloatingSub, rawOnly: true},
	"VMULPH":    {laneBits: 16, mode: amd64BinaryFloatingMul, rawOnly: true},
	"VDIVPH":    {laneBits: 16, mode: amd64BinaryFloatingDiv, rawOnly: true},
	"VMINPH":    {laneBits: 16, mode: amd64BinaryFloatingMin, sae: true, rawOnly: true},
	"VMAXPH":    {laneBits: 16, mode: amd64BinaryFloatingMax, sae: true, rawOnly: true},
	"VADDSH":    {laneBits: 16, mode: amd64BinaryFloatingAdd, scalar: true, rawOnly: true},
	"VSUBSH":    {laneBits: 16, mode: amd64BinaryFloatingSub, scalar: true, rawOnly: true},
	"VMULSH":    {laneBits: 16, mode: amd64BinaryFloatingMul, scalar: true, rawOnly: true},
	"VDIVSH":    {laneBits: 16, mode: amd64BinaryFloatingDiv, scalar: true, rawOnly: true},
	"VMINSH":    {laneBits: 16, mode: amd64BinaryFloatingMin, scalar: true, sae: true, rawOnly: true},
	"VMAXSH":    {laneBits: 16, mode: amd64BinaryFloatingMax, scalar: true, sae: true, rawOnly: true},
	"VADDPS":    {laneBits: 32, mode: amd64BinaryFloatingAdd},
	"VADDPD":    {laneBits: 64, mode: amd64BinaryFloatingAdd},
	"VADDSS":    {laneBits: 32, mode: amd64BinaryFloatingAdd, scalar: true},
	"VADDSD":    {laneBits: 64, mode: amd64BinaryFloatingAdd, scalar: true},
	"VSUBPS":    {laneBits: 32, mode: amd64BinaryFloatingSub},
	"VSUBPD":    {laneBits: 64, mode: amd64BinaryFloatingSub},
	"VSUBSS":    {laneBits: 32, mode: amd64BinaryFloatingSub, scalar: true},
	"VSUBSD":    {laneBits: 64, mode: amd64BinaryFloatingSub, scalar: true},
	"VMULPS":    {laneBits: 32, mode: amd64BinaryFloatingMul},
	"VMULPD":    {laneBits: 64, mode: amd64BinaryFloatingMul},
	"VMULSS":    {laneBits: 32, mode: amd64BinaryFloatingMul, scalar: true},
	"VMULSD":    {laneBits: 64, mode: amd64BinaryFloatingMul, scalar: true},
	"VDIVPS":    {laneBits: 32, mode: amd64BinaryFloatingDiv},
	"VDIVPD":    {laneBits: 64, mode: amd64BinaryFloatingDiv},
	"VDIVSS":    {laneBits: 32, mode: amd64BinaryFloatingDiv, scalar: true},
	"VDIVSD":    {laneBits: 64, mode: amd64BinaryFloatingDiv, scalar: true},
	"VMAXPS":    {laneBits: 32, mode: amd64BinaryFloatingMax, sae: true},
	"VMAXPD":    {laneBits: 64, mode: amd64BinaryFloatingMax, sae: true},
	"VMAXSS":    {laneBits: 32, mode: amd64BinaryFloatingMax, scalar: true, sae: true},
	"VMAXSD":    {laneBits: 64, mode: amd64BinaryFloatingMax, scalar: true, sae: true},
	"VMINPS":    {laneBits: 32, mode: amd64BinaryFloatingMin, sae: true},
	"VMINPD":    {laneBits: 64, mode: amd64BinaryFloatingMin, sae: true},
	"VMINSS":    {laneBits: 32, mode: amd64BinaryFloatingMin, scalar: true, sae: true},
	"VMINSD":    {laneBits: 64, mode: amd64BinaryFloatingMin, scalar: true, sae: true},
	"VSQRTSS":   {laneBits: 32, mode: amd64BinaryFloatingSqrt, scalar: true},
	"VSQRTSD":   {laneBits: 64, mode: amd64BinaryFloatingSqrt, scalar: true},
	"VSQRTSH":   {laneBits: 16, mode: amd64BinaryFloatingSqrt, scalar: true, rawOnly: true},
	"VSCALEFPS": {laneBits: 32, mode: amd64BinaryFloatingScale},
	"VSCALEFPD": {laneBits: 64, mode: amd64BinaryFloatingScale},
	"VSCALEFSS": {laneBits: 32, mode: amd64BinaryFloatingScale, scalar: true},
	"VSCALEFSD": {laneBits: 64, mode: amd64BinaryFloatingScale, scalar: true},
}

type amd64BinaryFloatingSuffix struct {
	broadcast bool
	zeroing   bool
	rounding  string
	sae       bool
}

func parseAMD64BinaryFloatingSuffix(suffix string) (amd64BinaryFloatingSuffix, bool) {
	switch suffix {
	case "":
		return amd64BinaryFloatingSuffix{}, true
	case "Z":
		return amd64BinaryFloatingSuffix{zeroing: true}, true
	case "BCST":
		return amd64BinaryFloatingSuffix{broadcast: true}, true
	case "BCST.Z":
		return amd64BinaryFloatingSuffix{broadcast: true, zeroing: true}, true
	case "SAE":
		return amd64BinaryFloatingSuffix{sae: true}, true
	case "SAE.Z":
		return amd64BinaryFloatingSuffix{sae: true, zeroing: true}, true
	case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
		return amd64BinaryFloatingSuffix{rounding: suffix}, true
	case "RN_SAE.Z", "RD_SAE.Z", "RU_SAE.Z", "RZ_SAE.Z":
		return amd64BinaryFloatingSuffix{rounding: strings.TrimSuffix(suffix, ".Z"), zeroing: true}, true
	default:
		return amd64BinaryFloatingSuffix{}, false
	}
}

func (c *amd64Ctx) lowerBinaryFloating(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64BinaryFloatingSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.rawOnly && !ins.x86Encoded {
		return true, false, fmt.Errorf("%s has no named Go assembler form: %q", baseOp, ins.Raw)
	}
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix {
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's binary floating optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar && properties.broadcast {
		return true, false, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.sae {
		if properties.rounding != "" {
			return true, false, fmt.Errorf("%s %s supports SAE, not explicit rounding: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if properties.sae {
		return true, false, fmt.Errorf("%s %s supports explicit rounding, not SAE: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects src1, src2, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked && !spec.rawOnly {
		return true, false, fmt.Errorf("386 %s mask forms exceed Go 1.27's assembler operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

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
		return true, false, fmt.Errorf("%s %s packed destination must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(destination, byteWidth) || !c.isGoEVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width Go 1.27 vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if (properties.rounding != "" || properties.sae) && !spec.scalar && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s packed rounding/SAE is available only for Z registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg {
		if !c.isGoEVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width and register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if properties.rounding != "" || properties.sae {
		return true, false, fmt.Errorf("%s %s explicit rounding/SAE requires a register first source: %q", c.goarch, baseOp, ins.Raw)
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		loadedMask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		mask = loadedMask
	}
	if spec.scalar {
		return c.lowerScalarBinaryFloating(spec, properties, ins, destination, mask)
	}
	return c.lowerPackedBinaryFloating(spec, properties, ins, destination, byteWidth, mask)
}

func (c *amd64Ctx) lowerPackedBinaryFloating(spec amd64BinaryFloatingSpec, properties amd64BinaryFloatingSuffix, ins Instr, destination Operand, byteWidth int, mask string) (bool, bool, error) {
	if spec.mode == amd64BinaryFloatingScale {
		return c.lowerPackedScaleF(spec, properties, ins.Args[0], ins.Args[1], destination, byteWidth, mask)
	}
	lanes := byteWidth * 8 / spec.laneBits
	llvmType := amd64FMA3LLVMType(lanes, spec.laneBits)
	load := func(operand Operand, allowBroadcast bool) (string, error) {
		if allowBroadcast && properties.broadcast {
			var scalar string
			var err error
			switch spec.laneBits {
			case 16:
				bits, loadErr := c.loadPackedBroadcastScalar(operand, 16, ins.x86Encoded)
				if loadErr != nil {
					return "", loadErr
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = bitcast i16 %s to half\n", value, bits)
				scalar = "%" + value
			case 32:
				scalar, err = c.evalF32(operand)
			case 64:
				scalar, err = c.evalF64(operand)
			}
			if err != nil {
				return "", err
			}
			return c.splatFMA3Scalar(lanes, spec.laneBits, scalar), nil
		}
		bytesValue, err := c.loadPackedCompareBytes(operand, byteWidth)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, byteWidth, bytesValue, llvmType)
		return "%" + value, nil
	}
	first, err := load(ins.Args[0], true)
	if err != nil {
		return true, false, err
	}
	second, err := load(ins.Args[1], false)
	if err != nil {
		return true, false, err
	}
	computed := c.emitBinaryFloating(spec, llvmType, lanes, second, first, properties.rounding)
	if mask != "" {
		computedBits := c.bitcastFloatingToIntegerLanes(llvmType, lanes, spec.laneBits, computed)
		oldBytes, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
		if loadErr != nil {
			return true, false, loadErr
		}
		oldBits := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, spec.laneBits, oldBytes)
		masked := amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computedBits, oldBits, mask, properties.zeroing)
		back := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to %s\n", back, lanes, spec.laneBits, masked, llvmType)
		computed = "%" + back
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, llvmType, computed, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarBinaryFloating(spec amd64BinaryFloatingSpec, properties amd64BinaryFloatingSuffix, ins Instr, destination Operand, mask string) (bool, bool, error) {
	if spec.mode == amd64BinaryFloatingScale {
		return c.lowerScalarScaleF(spec, properties, ins.Args[0], ins.Args[1], destination, mask)
	}
	var first, second string
	var err error
	if spec.laneBits == 16 {
		var firstBits, secondBits string
		if ins.Args[0].Kind == OpReg {
			firstBits, err = c.loadXLowInteger(ins.Args[0].Reg, 16)
		} else if mask != "" {
			firstBits, err = c.loadVectorScalarMemory(ins.Args[0], 16, mask)
		} else {
			firstBits, err = c.evalIntSized(ins.Args[0], "i16")
		}
		if err == nil {
			secondBits, err = c.loadXLowInteger(ins.Args[1].Reg, 16)
		}
		if err == nil {
			firstTemp, secondTemp := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast i16 %s to half\n", firstTemp, firstBits)
			fmt.Fprintf(c.b, "  %%%s = bitcast i16 %s to half\n", secondTemp, secondBits)
			first, second = "%"+firstTemp, "%"+secondTemp
		}
	} else if spec.laneBits == 32 {
		first, err = c.evalF32(ins.Args[0])
		if err == nil {
			second, err = c.loadXLowF32(ins.Args[1].Reg)
		}
	} else {
		first, err = c.evalF64(ins.Args[0])
		if err == nil {
			second, err = c.loadXLowF64(ins.Args[1].Reg)
		}
	}
	if err != nil {
		return true, false, err
	}
	llvmType := amd64FMA3LLVMType(1, spec.laneBits)
	computed := c.emitBinaryFloating(spec, llvmType, 1, second, first, properties.rounding)
	computedBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", computedBits, llvmType, computed, spec.laneBits)
	secondBytes, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, secondBytes)
	if spec.rawOnly {
		return true, false, c.storeScalarMoveRegister(destination.Reg, spec.laneBits, "%"+computedBits, base, mask, properties.zeroing)
	}
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+computedBits, base, mask, properties.zeroing)
}

func (c *amd64Ctx) emitBinaryFloating(spec amd64BinaryFloatingSpec, llvmType string, lanes int, left, right, rounding string) string {
	result := c.newTmp()
	switch spec.mode {
	case amd64BinaryFloatingSqrt:
		if rounding == "" {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.sqrt.%s(%s %s)\n", result, llvmType, amd64BinaryFloatingIntrinsicSuffix(lanes, spec.laneBits), llvmType, right)
		} else {
			intrinsic := fmt.Sprintf("llvm.experimental.constrained.sqrt.%s", amd64BinaryFloatingIntrinsicSuffix(lanes, spec.laneBits))
			fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", result, llvmType, intrinsic, llvmType, right, amd64FMA3RoundingMetadata(rounding))
		}
	case amd64BinaryFloatingMax, amd64BinaryFloatingMin:
		predicate := "ogt"
		if spec.mode == amd64BinaryFloatingMin {
			predicate = "olt"
		}
		comparison := c.newTmp()
		predicateType := "i1"
		if lanes > 1 {
			predicateType = fmt.Sprintf("<%d x i1>", lanes)
		}
		fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", comparison, predicate, llvmType, left, right)
		fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %s, %s %s\n", result, predicateType, comparison, llvmType, left, llvmType, right)
	default:
		operation := "fadd"
		switch spec.mode {
		case amd64BinaryFloatingSub:
			operation = "fsub"
		case amd64BinaryFloatingMul:
			operation = "fmul"
		case amd64BinaryFloatingDiv:
			operation = "fdiv"
		}
		if rounding == "" {
			fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, operation, llvmType, left, right)
		} else {
			intrinsic := fmt.Sprintf("llvm.experimental.constrained.%s.%s", operation, amd64BinaryFloatingIntrinsicSuffix(lanes, spec.laneBits))
			fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", result, llvmType, intrinsic, llvmType, left, llvmType, right, amd64FMA3RoundingMetadata(rounding))
		}
	}
	return "%" + result
}

func (c *amd64Ctx) bitcastFloatingToIntegerLanes(llvmType string, lanes, laneBits int, value string) string {
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i%d>\n", result, llvmType, value, lanes, laneBits)
	return "%" + result
}

func amd64BinaryFloatingIntrinsicSuffix(lanes, laneBits int) string {
	suffix := "f32"
	if laneBits == 16 {
		suffix = "f16"
	} else if laneBits == 64 {
		suffix = "f64"
	}
	if lanes > 1 {
		return fmt.Sprintf("v%d%s", lanes, suffix)
	}
	return suffix
}
