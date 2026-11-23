package plan9asm

import "fmt"

type arm64RawReciprocalEstimate struct {
	intrinsic   string
	scalar      bool
	binary      bool
	unsigned    bool
	arrangement arm64VectorArrangement
	source      int
	second      int
	destination int
}

type arm64ReciprocalSpec struct {
	intrinsic   string
	elementBits int
	unsigned    bool
}

// The vector rows have Q cleared. Its value selects 64 or 128 active bits
// independently of the operation and element width. Scalar rows retain Q.
var arm64ReciprocalUnary = map[uint32]arm64ReciprocalSpec{
	0x5ef9d800: {"frecpe", 16, false},
	0x5ea1d800: {"frecpe", 32, false},
	0x5ee1d800: {"frecpe", 64, false},
	0x0ef9d800: {"frecpe", 16, false},
	0x0ea1d800: {"frecpe", 32, false},
	0x0ee1d800: {"frecpe", 64, false},
	0x5ef9f800: {"frecpx", 16, false},
	0x5ea1f800: {"frecpx", 32, false},
	0x5ee1f800: {"frecpx", 64, false},
	0x7ef9d800: {"frsqrte", 16, false},
	0x7ea1d800: {"frsqrte", 32, false},
	0x7ee1d800: {"frsqrte", 64, false},
	0x2ef9d800: {"frsqrte", 16, false},
	0x2ea1d800: {"frsqrte", 32, false},
	0x2ee1d800: {"frsqrte", 64, false},
	0x0ea1c800: {"urecpe", 32, true},
	0x2ea1c800: {"ursqrte", 32, true},
}

var arm64ReciprocalBinary = map[uint32]arm64ReciprocalSpec{
	0x5e403c00: {"frecps", 16, false},
	0x5e20fc00: {"frecps", 32, false},
	0x5e60fc00: {"frecps", 64, false},
	0x0e403c00: {"frecps", 16, false},
	0x0e20fc00: {"frecps", 32, false},
	0x0e60fc00: {"frecps", 64, false},
	0x5ec03c00: {"frsqrts", 16, false},
	0x5ea0fc00: {"frsqrts", 32, false},
	0x5ee0fc00: {"frsqrts", 64, false},
	0x0ec03c00: {"frsqrts", 16, false},
	0x0ea0fc00: {"frsqrts", 32, false},
	0x0ee0fc00: {"frsqrts", 64, false},
}

func decodeARM64RawReciprocalEstimate(word uint32) (arm64RawReciprocalEstimate, bool) {
	const registers = uint32(31 | 31<<5)
	key := word &^ registers
	scalar := word&(1<<28) != 0
	if !scalar {
		key &^= 1 << 30
	}
	spec, ok := arm64ReciprocalUnary[key]
	binary := !ok
	if binary {
		spec, ok = arm64ReciprocalBinary[key&^(31<<16)]
	}
	if !ok {
		return arm64RawReciprocalEstimate{}, false
	}

	lanes := 1
	if !scalar {
		lanes = (64 << (word >> 30 & 1)) / spec.elementBits
		if lanes == 1 { // Vector 1D encodings are reserved.
			return arm64RawReciprocalEstimate{}, false
		}
	}
	return arm64RawReciprocalEstimate{
		intrinsic:   spec.intrinsic,
		scalar:      scalar,
		binary:      binary,
		unsigned:    spec.unsigned,
		arrangement: arm64VectorArrangement{elementBits: spec.elementBits, lanes: lanes},
		source:      int(word>>5) & 31,
		second:      int(word>>16) & 31,
		destination: int(word) & 31,
	}, true
}

func (c *arm64Ctx) lowerRawReciprocalEstimate(form arm64RawReciprocalEstimate) error {
	if form.unsigned {
		return c.lowerARM64UnsignedReciprocalEstimate(form)
	}
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

func (c *arm64Ctx) lowerARM64UnsignedReciprocalEstimate(form arm64RawReciprocalEstimate) error {
	arrangement := form.arrangement
	source, err := c.loadARM64VectorInteger(Reg(fmt.Sprintf("V%d", form.source)), arrangement)
	if err != nil {
		return err
	}
	typ := fmt.Sprintf("<%d x i32>", arrangement.lanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.v%di32(%s %s)\n",
		result, typ, form.intrinsic, arrangement.lanes, typ, source)
	return c.storeARM64VectorInteger(Reg(fmt.Sprintf("V%d", form.destination)), arrangement, "%"+result)
}
