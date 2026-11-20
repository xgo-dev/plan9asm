package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

// lowerARM64VectorFloatImmediate handles the Advanced SIMD floating-point
// modified-immediate form. x/arch prints this raw encoding as FMOV $f, Vd.T;
// Go's named optab has no VFMOV spelling, so keep the decoder spelling and
// lower it directly to the repeated IEEE value (with inactive lanes zero).
func (c *arm64Ctx) lowerARM64VectorFloatImmediate(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "FMOV" || len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
		return false, false, nil
	}
	if !ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" {
		return true, false, fmt.Errorf("arm64 FMOV vector immediate requires a resolved floating constant: %q", ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !valid || !((arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && (arrangement.lanes == 2 || arrangement.lanes == 4)) ||
		(arrangement.elementBits == 64 && arrangement.lanes == 2)) {
		return true, false, fmt.Errorf("arm64 FMOV vector immediate requires H4/H8, S2/S4, or D2 destination: %q", ins.Raw)
	}
	value := math.Float64frombits(uint64(ins.Args[0].Imm))
	laneValue := math.Float64bits(value)
	if arrangement.elementBits == 16 {
		laneValue = uint64(arm64Float16Bits(value))
	} else if arrangement.elementBits == 32 {
		laneValue = uint64(math.Float32bits(float32(value)))
	}
	if err := c.lowerARM64VectorFloatImmediateBits(arrangement, laneValue, ins.Args[1].Reg); err != nil {
		return true, false, err
	}
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64VectorFloatImmediateBits(
	arrangement arm64VectorArrangement,
	laneValue uint64,
	destination Reg,
) error {
	physicalLanes := 128 / arrangement.elementBits
	values := make([]string, physicalLanes)
	for i := range values {
		if i >= arrangement.lanes {
			values[i] = "0"
			continue
		}
		values[i] = fmt.Sprintf("%d", laneValue)
	}
	elements := make([]string, len(values))
	for i, element := range values {
		elements[i] = fmt.Sprintf("i%d %s", arrangement.elementBits, element)
	}
	vector := c.newTmp()
	vectorType := fmt.Sprintf("<%d x i%d>", physicalLanes, arrangement.elementBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s <%s> to <16 x i8>\n", vector, vectorType, strings.Join(elements, ", "))
	return c.storeVReg(destination, "%"+vector)
}

// arm64Float16Bits converts the ordinary floating-point constant used by the
// parser into IEEE binary16 bits for the H-form modified immediate.
func arm64Float16Bits(value float64) uint16 {
	bits := math.Float32bits(float32(value))
	sign := uint16((bits >> 16) & 0x8000)
	exponent := int((bits >> 23) & 0xff)
	fraction := bits & 0x7fffff
	if exponent == 0xff {
		if fraction == 0 {
			return sign | 0x7c00
		}
		return sign | 0x7e00
	}
	exponent -= 127
	if exponent < -24 {
		return sign
	}
	if exponent < -14 {
		shift := uint(-exponent - 14)
		mantissa := (fraction | 0x800000) >> (shift + 1)
		if (fraction|0x800000)&(1<<shift) != 0 {
			mantissa++
		}
		return sign | uint16(mantissa)
	}
	if exponent > 15 {
		return sign | 0x7c00
	}
	halfExponent := uint16(exponent+15) << 10
	mantissa := fraction >> 13
	if fraction&0x1000 != 0 {
		mantissa++
		if mantissa == 0x400 {
			return sign | halfExponent + 0x400
		}
	}
	return sign | halfExponent | uint16(mantissa)
}
