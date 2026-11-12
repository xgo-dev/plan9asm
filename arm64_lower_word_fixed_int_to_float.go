package plan9asm

import (
	"fmt"
	"math"
	"strconv"
)

// SCVTF and UCVTF have three distinct fixed-point encodings: a general
// register to scalar float, an Advanced SIMD scalar, and an Advanced SIMD
// vector. The unscaled forms use different opcodes and remain separate.
type arm64RawFixedIntToFloat struct {
	unsigned       bool
	scalar         bool
	vectorSource   bool
	integerBits    int
	fractionalBits int
	vectorBits     int
	source         int
	destination    int
}

func decodeARM64RawFixedIntToFloat(word uint32) (arm64RawFixedIntToFloat, bool) {
	const (
		gpVariable = uint32(1<<31 | 1<<22 | 1<<16 | 63<<10 | 31<<5 | 31)
		gpBase     = uint32(0x1e020000)
	)
	if word&^gpVariable == gpBase {
		integerBits := 32
		if word&(1<<31) != 0 {
			integerBits = 64
		}
		fractionalBits := 64 - int(word>>10&63)
		if fractionalBits > integerBits {
			return arm64RawFixedIntToFloat{}, false
		}
		floatBits := 32
		if word&(1<<22) != 0 {
			floatBits = 64
		}
		return arm64RawFixedIntToFloat{
			unsigned:       word&(1<<16) != 0,
			scalar:         true,
			integerBits:    integerBits,
			fractionalBits: fractionalBits,
			vectorBits:     floatBits,
			source:         int(word>>5) & 31,
			destination:    int(word) & 31,
		}, true
	}

	maskedScalar := word & 0xff80fc00
	maskedVector := word & 0xbf80fc00
	scalar := maskedScalar == 0x5f00e400 || maskedScalar == 0x7f00e400
	vector := maskedVector == 0x0f00e400 || maskedVector == 0x2f00e400
	if !scalar && !vector {
		return arm64RawFixedIntToFloat{}, false
	}

	immh := int(word>>19) & 15
	integerBits := 0
	switch {
	case immh >= 8:
		integerBits = 64
	case immh >= 4:
		integerBits = 32
	default:
		return arm64RawFixedIntToFloat{}, false
	}
	vectorBits := integerBits
	if vector {
		vectorBits = 64
		if word&(1<<30) != 0 {
			vectorBits = 128
		}
		if integerBits == 64 && vectorBits == 64 {
			return arm64RawFixedIntToFloat{}, false
		}
	}
	fractionalBits := 2*integerBits - int(word>>16&127)
	if fractionalBits < 1 || fractionalBits > integerBits {
		return arm64RawFixedIntToFloat{}, false
	}
	return arm64RawFixedIntToFloat{
		unsigned:       word&(1<<29) != 0,
		scalar:         scalar,
		vectorSource:   true,
		integerBits:    integerBits,
		fractionalBits: fractionalBits,
		vectorBits:     vectorBits,
		source:         int(word>>5) & 31,
		destination:    int(word) & 31,
	}, true
}

func arm64FixedIntToFloatScale(bits int) string {
	return strconv.FormatFloat(math.Ldexp(1, -bits), 'e', 17, 64)
}

func (c *arm64Ctx) lowerRawFixedIntToFloat(form arm64RawFixedIntToFloat) error {
	conversion := "sitofp"
	if form.unsigned {
		conversion = "uitofp"
	}
	floatType := "float"
	floatBits := form.integerBits
	if form.scalar {
		floatBits = form.vectorBits
	}
	if floatBits == 64 {
		floatType = "double"
	}
	scale := arm64FixedIntToFloatScale(form.fractionalBits)
	sourceReg := Reg(fmt.Sprintf("R%d", form.source))
	if form.vectorSource {
		sourceReg = Reg(fmt.Sprintf("F%d", form.source))
	} else if form.source == 31 {
		sourceReg = ZR
	}
	destinationReg := Reg(fmt.Sprintf("F%d", form.destination))

	if form.scalar {
		source, err := c.loadReg(sourceReg)
		if err != nil {
			return err
		}
		if form.integerBits == 32 {
			narrow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, source)
			source = "%" + narrow
		}
		converted := c.newTmp()
		scaled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s i%d %s to %s\n", converted, conversion, form.integerBits, source, floatType)
		fmt.Fprintf(c.b, "  %%%s = fmul %s %%%s, %s\n", scaled, floatType, converted, scale)
		return c.storeARM64ScalarFloatReg(destinationReg, form.vectorBits, "%"+scaled)
	}

	arrangement := arm64VectorArrangement{
		elementBits: form.integerBits,
		lanes:       form.vectorBits / form.integerBits,
	}
	vectorSource := Reg(fmt.Sprintf("V%d", form.source))
	vectorDestination := Reg(fmt.Sprintf("V%d", form.destination))
	source, err := c.loadARM64VectorInteger(vectorSource, arrangement)
	if err != nil {
		return err
	}
	converted := c.newTmp()
	scaled := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %s to <%d x %s>\n",
		converted, conversion, arrangement.lanes, form.integerBits, source, arrangement.lanes, floatType)
	fmt.Fprintf(c.b, "  %%%s = fmul <%d x %s> %%%s, <", scaled, arrangement.lanes, floatType, converted)
	for lane := 0; lane < arrangement.lanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "%s %s", floatType, scale)
	}
	c.b.WriteString(">\n")
	return c.storeARM64VectorFloat(vectorDestination, arrangement, "%"+scaled)
}
