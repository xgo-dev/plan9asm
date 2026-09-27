package plan9asm

import "fmt"

type arm64RawReciprocalEstimate struct {
	intrinsic   string
	scalar      bool
	binary      bool
	arrangement arm64VectorArrangement
	source      int
	second      int
	destination int
}

func decodeARM64RawReciprocalEstimate(word uint32) (arm64RawReciprocalEstimate, bool) {
	const registers = uint32(31 | 31<<5)
	forms := map[uint32]struct {
		intrinsic string
		scalar    bool
		bits      int
		lanes     int
	}{
		0x5ef9d800: {"frecpe", true, 16, 1},
		0x5ea1d800: {"frecpe", true, 32, 1},
		0x5ee1d800: {"frecpe", true, 64, 1},
		0x0ef9d800: {"frecpe", false, 16, 4},
		0x4ef9d800: {"frecpe", false, 16, 8},
		0x0ea1d800: {"frecpe", false, 32, 2},
		0x4ea1d800: {"frecpe", false, 32, 4},
		0x4ee1d800: {"frecpe", false, 64, 2},
		0x5ef9f800: {"frecpx", true, 16, 1},
		0x5ea1f800: {"frecpx", true, 32, 1},
		0x5ee1f800: {"frecpx", true, 64, 1},
		0x7ef9d800: {"frsqrte", true, 16, 1},
		0x7ea1d800: {"frsqrte", true, 32, 1},
		0x7ee1d800: {"frsqrte", true, 64, 1},
		0x2ef9d800: {"frsqrte", false, 16, 4},
		0x6ef9d800: {"frsqrte", false, 16, 8},
		0x2ea1d800: {"frsqrte", false, 32, 2},
		0x6ea1d800: {"frsqrte", false, 32, 4},
		0x6ee1d800: {"frsqrte", false, 64, 2},
	}
	decoded, ok := forms[word&^registers]
	if !ok {
		const binaryRegisters = registers | 31<<16
		binaryForms := map[uint32]struct {
			intrinsic string
			scalar    bool
			bits      int
			lanes     int
		}{
			0x5e403c00: {"frecps", true, 16, 1},
			0x5e20fc00: {"frecps", true, 32, 1},
			0x5e60fc00: {"frecps", true, 64, 1},
			0x0e403c00: {"frecps", false, 16, 4},
			0x4e403c00: {"frecps", false, 16, 8},
			0x0e20fc00: {"frecps", false, 32, 2},
			0x4e20fc00: {"frecps", false, 32, 4},
			0x4e60fc00: {"frecps", false, 64, 2},
			0x5ec03c00: {"frsqrts", true, 16, 1},
			0x5ea0fc00: {"frsqrts", true, 32, 1},
			0x5ee0fc00: {"frsqrts", true, 64, 1},
			0x0ec03c00: {"frsqrts", false, 16, 4},
			0x4ec03c00: {"frsqrts", false, 16, 8},
			0x0ea0fc00: {"frsqrts", false, 32, 2},
			0x4ea0fc00: {"frsqrts", false, 32, 4},
			0x4ee0fc00: {"frsqrts", false, 64, 2},
		}
		decoded, ok := binaryForms[word&^binaryRegisters]
		if !ok {
			return arm64RawReciprocalEstimate{}, false
		}
		return arm64RawReciprocalEstimate{
			intrinsic:   decoded.intrinsic,
			scalar:      decoded.scalar,
			binary:      true,
			arrangement: arm64VectorArrangement{elementBits: decoded.bits, lanes: decoded.lanes},
			source:      int(word>>5) & 31,
			second:      int(word>>16) & 31,
			destination: int(word) & 31,
		}, true
	}
	return arm64RawReciprocalEstimate{
		intrinsic:   decoded.intrinsic,
		scalar:      decoded.scalar,
		arrangement: arm64VectorArrangement{elementBits: decoded.bits, lanes: decoded.lanes},
		source:      int(word>>5) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawReciprocalEstimate(form arm64RawReciprocalEstimate) error {
	floatType, suffix, _ := arm64ScalarFloatType(form.arrangement.elementBits)
	if form.scalar {
		source, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.source)), form.arrangement.elementBits)
		if err != nil {
			return err
		}
		result := c.newTmp()
		if form.binary {
			second, err := c.loadARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.second)), form.arrangement.elementBits)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.%s(%s %s, %s %s)\n",
				result, floatType, form.intrinsic, suffix, floatType, source, floatType, second)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.%s(%s %s)\n",
				result, floatType, form.intrinsic, suffix, floatType, source)
		}
		return c.storeARM64ScalarFloatReg(Reg(fmt.Sprintf("F%d", form.destination)), form.arrangement.elementBits, "%"+result)
	}

	source, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.source)), form.arrangement)
	if err != nil {
		return err
	}
	vectorType := fmt.Sprintf("<%d x %s>", form.arrangement.lanes, floatType)
	result := c.newTmp()
	if form.binary {
		second, err := c.loadARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.second)), form.arrangement)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%d%s(%s %s, %s %s)\n",
			result, vectorType, form.intrinsic, form.arrangement.lanes, suffix, vectorType, source, vectorType, second)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%d%s(%s %s)\n",
			result, vectorType, form.intrinsic, form.arrangement.lanes, suffix, vectorType, source)
	}
	return c.storeARM64VectorFloat(Reg(fmt.Sprintf("V%d", form.destination)), form.arrangement, "%"+result)
}
