package plan9asm

import (
	"fmt"
	"strings"
)

type arm64RawFloatPairwiseMinMax struct {
	operation   string
	scalar      bool
	arrangement arm64VectorArrangement
	first       int
	second      int
	destination int
}

func arm64LLVMShuffleMask(indices []int) string {
	values := make([]string, len(indices))
	for i, index := range indices {
		values[i] = fmt.Sprintf("i32 %d", index)
	}
	return fmt.Sprintf("<%d x i32> <%s>", len(indices), strings.Join(values, ", "))
}

func decodeARM64RawFloatPairwiseMinMax(word uint32) (arm64RawFloatPairwiseMinMax, bool) {
	const vectorRegisters = uint32(31 | 31<<5 | 31<<16)
	vectorForms := map[uint32]struct {
		operation string
		bits      int
		lanes     int
	}{
		0x2e403400: {"maximum", 16, 4}, 0x6e403400: {"maximum", 16, 8},
		0x2e20f400: {"maximum", 32, 2}, 0x6e20f400: {"maximum", 32, 4}, 0x6e60f400: {"maximum", 64, 2},
		0x2ec03400: {"minimum", 16, 4}, 0x6ec03400: {"minimum", 16, 8},
		0x2ea0f400: {"minimum", 32, 2}, 0x6ea0f400: {"minimum", 32, 4}, 0x6ee0f400: {"minimum", 64, 2},
		0x2e400400: {"maxnum", 16, 4}, 0x6e400400: {"maxnum", 16, 8},
		0x2e20c400: {"maxnum", 32, 2}, 0x6e20c400: {"maxnum", 32, 4}, 0x6e60c400: {"maxnum", 64, 2},
		0x2ec00400: {"minnum", 16, 4}, 0x6ec00400: {"minnum", 16, 8},
		0x2ea0c400: {"minnum", 32, 2}, 0x6ea0c400: {"minnum", 32, 4}, 0x6ee0c400: {"minnum", 64, 2},
	}
	if form, ok := vectorForms[word&^vectorRegisters]; ok {
		return arm64RawFloatPairwiseMinMax{
			operation: form.operation,
			arrangement: arm64VectorArrangement{
				elementBits: form.bits,
				lanes:       form.lanes,
			},
			first:       int(word>>5) & 31,
			second:      int(word>>16) & 31,
			destination: int(word) & 31,
		}, true
	}

	const scalarRegisters = uint32(31 | 31<<5)
	scalarForms := map[uint32]struct {
		operation string
		bits      int
	}{
		0x5e30f800: {"maximum", 16}, 0x7e30f800: {"maximum", 32}, 0x7e70f800: {"maximum", 64},
		0x5eb0f800: {"minimum", 16}, 0x7eb0f800: {"minimum", 32}, 0x7ef0f800: {"minimum", 64},
		0x5e30c800: {"maxnum", 16}, 0x7e30c800: {"maxnum", 32}, 0x7e70c800: {"maxnum", 64},
		0x5eb0c800: {"minnum", 16}, 0x7eb0c800: {"minnum", 32}, 0x7ef0c800: {"minnum", 64},
	}
	if form, ok := scalarForms[word&^scalarRegisters]; ok {
		return arm64RawFloatPairwiseMinMax{
			operation:   form.operation,
			scalar:      true,
			arrangement: arm64VectorArrangement{elementBits: form.bits, lanes: 2},
			first:       int(word>>5) & 31,
			second:      -1,
			destination: int(word) & 31,
		}, true
	}
	return arm64RawFloatPairwiseMinMax{}, false
}

func (c *arm64Ctx) lowerRawFloatPairwiseMinMax(form arm64RawFloatPairwiseMinMax) error {
	first, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.first)), form.arrangement)
	if err != nil {
		return err
	}
	floatType := arm64RawFloatType(form.arrangement.elementBits)
	intrinsicSuffix := fmt.Sprintf("f%d", form.arrangement.elementBits)
	if form.scalar {
		left := c.newTmp()
		right := c.newTmp()
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x %s> %s, i32 0\n", left, floatType, first)
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x %s> %s, i32 1\n", right, floatType, first)
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s, %s %%%s)\n",
			result, floatType, form.operation, intrinsicSuffix, floatType, left, floatType, right)
		return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), form.arrangement.elementBits, "%"+result)
	}

	second, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.second)), form.arrangement)
	if err != nil {
		return err
	}
	lanes := form.arrangement.lanes
	leftMask := make([]int, 0, lanes)
	rightMask := make([]int, 0, lanes)
	for source := 0; source < 2; source++ {
		base := source * lanes
		for lane := 0; lane < lanes/2; lane++ {
			leftMask = append(leftMask, base+lane*2)
			rightMask = append(rightMask, base+lane*2+1)
		}
	}
	left := c.newTmp()
	right := c.newTmp()
	vectorType := fmt.Sprintf("<%d x %s>", lanes, floatType)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", left, vectorType, first, vectorType, second, arm64LLVMShuffleMask(leftMask))
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %s, %s %s, %s\n", right, vectorType, first, vectorType, second, arm64LLVMShuffleMask(rightMask))
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.v%d%s(%s %%%s, %s %%%s)\n",
		result, vectorType, form.operation, lanes, intrinsicSuffix, vectorType, left, vectorType, right)
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
}
