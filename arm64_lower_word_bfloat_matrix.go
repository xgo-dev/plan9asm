package plan9asm

import "fmt"

// arm64RawBFloatMatrix is the 128-bit Advanced SIMD BFMMLA encoding. LLVM's
// architecture intrinsic retains BF16 matrix ordering and rounding semantics.
type arm64RawBFloatMatrix struct {
	destination int
	left        int
	right       int
}

func decodeARM64RawBFloatMatrix(word uint32) (arm64RawBFloatMatrix, bool) {
	const registers = uint32(31<<16 | 31<<5 | 31)
	if word&^registers != 0x6e40ec00 {
		return arm64RawBFloatMatrix{}, false
	}
	return arm64RawBFloatMatrix{
		destination: int(word) & 31,
		left:        int(word>>5) & 31,
		right:       int(word>>16) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawBFloatMatrix(form arm64RawBFloatMatrix) error {
	accumulatorReg := Reg(fmt.Sprintf("V%d", form.destination))
	accumulatorArrangement := arm64VectorArrangement{elementBits: 32, lanes: 4}
	inputArrangement := arm64VectorArrangement{elementBits: 16, lanes: 8}

	accumulator, err := c.loadARM64VectorFloat(accumulatorReg, accumulatorArrangement)
	if err != nil {
		return err
	}
	loadBFloat := func(register int) (string, error) {
		integer, err := c.loadARM64VectorInteger(
			Reg(fmt.Sprintf("V%d", register)), inputArrangement)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <8 x i16> %s to <8 x bfloat>\n", value, integer)
		return "%" + value, nil
	}
	left, err := loadBFloat(form.left)
	if err != nil {
		return err
	}
	right, err := loadBFloat(form.right)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b,
		"  %%%s = call <4 x float> @llvm.aarch64.neon.bfmmla(<4 x float> %s, <8 x bfloat> %s, <8 x bfloat> %s)\n",
		result, accumulator, left, right)
	return c.storeARM64VectorFloat(accumulatorReg, accumulatorArrangement, "%"+result)
}
