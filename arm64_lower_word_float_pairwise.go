package plan9asm

import (
	"fmt"
	"strings"
)

type arm64FloatPairwiseOp uint8

const (
	arm64FloatPairwiseAdd arm64FloatPairwiseOp = iota
	arm64FloatPairwiseMax
	arm64FloatPairwiseMin
	arm64FloatPairwiseMaxNum
	arm64FloatPairwiseMinNum
)

var arm64FloatPairwiseMnemonics = [...]string{"faddp", "fmaxp", "fminp", "fmaxnmp", "fminnmp"}
var arm64FloatPairwiseIntrinsics = [...]string{"", "maximum", "minimum", "maxnum", "minnum"}

var arm64GoFloatPairwiseOps = map[Op]arm64FloatPairwiseOp{
	"VFADDP":   arm64FloatPairwiseAdd,
	"VFMAXP":   arm64FloatPairwiseMax,
	"VFMINP":   arm64FloatPairwiseMin,
	"VFMAXNMP": arm64FloatPairwiseMaxNum,
	"VFMINNMP": arm64FloatPairwiseMinNum,
}

// first and second are in architectural Rn, Rm order. A scalar result
// reduces two lanes of first and has no second source.
type arm64FloatPairwiseForm struct {
	op                         arm64FloatPairwiseOp
	scalar                     bool
	arrangement                arm64VectorArrangement
	first, second, destination Reg
}

func decodeARM64RawFloatPairwise(word uint32) (arm64FloatPairwiseForm, bool) {
	const registers = 31 | 31<<5
	const size = 1 << 22
	const q = 1 << 30
	scalar := word&(1<<28) != 0
	key := word &^ (registers | size | q | 31<<16)
	if scalar {
		key = word &^ (registers | size | 1<<29)
	}

	var op arm64FloatPairwiseOp
	switch key {
	case 0x2e001400, 0x2e20d400, 0x5e30d800:
		op = arm64FloatPairwiseAdd
	case 0x2e003400, 0x2e20f400, 0x5e30f800:
		op = arm64FloatPairwiseMax
	case 0x2e803400, 0x2ea0f400, 0x5eb0f800:
		op = arm64FloatPairwiseMin
	case 0x2e000400, 0x2e20c400, 0x5e30c800:
		op = arm64FloatPairwiseMaxNum
	case 0x2e800400, 0x2ea0c400, 0x5eb0c800:
		op = arm64FloatPairwiseMinNum
	default:
		return arm64FloatPairwiseForm{}, false
	}

	bits, lanes := 32, 2
	if word&size != 0 {
		bits = 64
	}
	var second Reg
	if scalar {
		if word&(1<<29) == 0 {
			if word&size != 0 {
				return arm64FloatPairwiseForm{}, false
			}
			bits = 16
		}
	} else {
		if word&(1<<21) == 0 {
			if word&size == 0 {
				return arm64FloatPairwiseForm{}, false
			}
			bits = 16
		}
		vectorBits := 64
		if word&q != 0 {
			vectorBits = 128
		}
		lanes = vectorBits / bits
		if lanes < 2 {
			return arm64FloatPairwiseForm{}, false
		}
		second = Reg(fmt.Sprintf("V%d", word>>16&31))
	}
	destinationBank := "V"
	if scalar {
		destinationBank = "F"
	}
	return arm64FloatPairwiseForm{
		op: op, scalar: scalar, arrangement: arm64VectorArrangement{elementBits: bits, lanes: lanes},
		first: Reg(fmt.Sprintf("V%d", word>>5&31)), second: second,
		destination: Reg(fmt.Sprintf("%s%d", destinationBank, word&31)),
	}, true
}

func (c *arm64Ctx) lowerARM64FloatPairwise(form arm64FloatPairwiseForm) error {
	bits, lanes := form.arrangement.elementBits, form.arrangement.lanes
	if arm64ScalarConversionNativeTarget(c.targetTriple) {
		// One original operation preserves dynamic rounding and FPSR even if
		// the result is unused. Native writes also clear the inactive V bits.
		first, err := c.loadVRegWidth(form.first, bits*lanes)
		if err != nil {
			return err
		}
		mnemonic := arm64FloatPairwiseMnemonics[form.op]
		modifier := arm64ScalarConversionModifier(bits, false)
		result := c.newTmp()
		if form.scalar {
			operation := fmt.Sprintf("%s ${0:%s}, $1.2%s", mnemonic, modifier, modifier)
			c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(<16 x i8> %s)\n",
				result, operation, "=w,w,~{memory}", first)
		} else {
			second, err := c.loadVRegWidth(form.second, bits*lanes)
			if err != nil {
				return err
			}
			layout := fmt.Sprintf("%d%s", lanes, modifier)
			operation := fmt.Sprintf("%s $0.%s, $1.%s, $2.%s", mnemonic, layout, layout, layout)
			c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(<16 x i8> %s, <16 x i8> %s)\n",
				result, operation, "=w,w,w,~{memory}", first, second)
		}
		return c.storeVReg(form.destination, "%"+result)
	}

	return c.lowerARM64PortableFloatPairwise(form)
}

func (c *arm64Ctx) lowerARM64PortableFloatPairwise(form arm64FloatPairwiseForm) error {
	first, err := c.loadARM64VectorFloat(form.first, form.arrangement)
	if err != nil {
		return err
	}
	bits, lanes := form.arrangement.elementBits, form.arrangement.lanes
	floatType, suffix, _ := arm64ScalarFloatType(bits)
	vectorType := fmt.Sprintf("<%d x %s>", lanes, floatType)
	valueType := floatType
	left, right := c.newTmp(), c.newTmp()
	if form.scalar {
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 0\n", left, vectorType, first)
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 1\n", right, vectorType, first)
	} else {
		second, err := c.loadARM64VectorFloat(form.second, form.arrangement)
		if err != nil {
			return err
		}
		valueType, suffix = vectorType, fmt.Sprintf("v%d%s", lanes, suffix)
		even, odd := make([]int, lanes), make([]int, lanes)
		for i := range even {
			even[i], odd[i] = 2*i, 2*i+1
		}
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", left, vectorType, first, vectorType, second, arm64LLVMShuffleMask(even))
		fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", right, vectorType, first, vectorType, second, arm64LLVMShuffleMask(odd))
	}

	result := c.newTmp()
	if form.op == arm64FloatPairwiseAdd {
		fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", result, valueType, left, right)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s, %s %%%s)\n",
			result, valueType, arm64FloatPairwiseIntrinsics[form.op], suffix, valueType, left, valueType, right)
	}
	if form.scalar {
		return c.storeARM64ScalarFloatReg(form.destination, bits, "%"+result)
	}
	return c.storeARM64VectorFloat(form.destination, form.arrangement, "%"+result)
}

func arm64LLVMShuffleMask(indices []int) string {
	values := make([]string, len(indices))
	for i, index := range indices {
		values[i] = fmt.Sprintf("i32 %d", index)
	}
	return fmt.Sprintf("<%d x i32> <%s>", len(indices), strings.Join(values, ", "))
}

func arm64RawFloatType(bits int) string {
	name, _, ok := arm64ScalarFloatType(bits)
	if !ok {
		panic(fmt.Sprintf("unsupported ARM64 floating width %d", bits))
	}
	return name
}
