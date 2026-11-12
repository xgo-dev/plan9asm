package plan9asm

import (
	"math"
	"math/bits"
	"testing"
)

// Test-only independent FPToFixed/FixedToFP reference. Production never uses
// software rounding, saturation or invented FPSR. Each expected full-bank row
// is first checked by an original Go object under QEMU before LLVM comparison.
func arm64ScalarConversionReference(fixture arm64ScalarConversionFixture, value, control uint64) (uint64, uint64) {
	fraction, exponentBits, bias := 52, 11, 1023
	if fixture.floatBits == 32 {
		fraction, exponentBits, bias = 23, 8, 127
	} else if fixture.floatBits == 16 {
		fraction, exponentBits, bias = 10, 5, 15
	}
	floatSign := uint64(1) << uint(fixture.floatBits-1)
	integerMask := ^uint64(0) >> uint(64-fixture.integerBits)
	if fixture.toFloat {
		value &= integerMask
		negative := !fixture.unsigned && value>>(fixture.integerBits-1) != 0
		magnitude := value
		if negative {
			magnitude = -value & integerMask
		}
		if magnitude == 0 {
			return 0, 0
		}
		exponent := bits.Len64(magnitude) - 1
		shift := exponent - fraction
		significand, remainder := magnitude, uint64(0)
		if shift > 0 {
			significand = magnitude >> uint(shift)
			remainder = magnitude & (uint64(1)<<uint(shift) - 1)
		} else {
			significand <<= uint(-shift)
		}
		rounding := control >> 22 & 3
		up := false
		if remainder != 0 {
			switch rounding {
			case 0:
				half := uint64(1) << uint(shift-1)
				up = remainder > half || remainder == half && significand&1 != 0
			case 1:
				up = !negative
			case 2:
				up = negative
			}
		}
		if up {
			significand++
			if significand == uint64(1)<<uint(fraction+1) {
				significand >>= 1
				exponent++
			}
		}
		flags := uint64(0)
		if remainder != 0 {
			flags = 0x10
		}
		result := uint64(exponent+bias)<<uint(fraction) | significand&(uint64(1)<<uint(fraction)-1)
		if exponent > bias {
			// Integer->half can overflow; S/D cannot for a 64-bit integer.
			infinity := (uint64(1)<<uint(exponentBits) - 1) << uint(fraction)
			result = infinity - 1
			if rounding == 0 || rounding == 1 && !negative || rounding == 2 && negative {
				result = infinity
			}
			flags = 0x14 // OFC | IXC, including directed finite saturation.
		}
		if negative {
			result |= floatSign
		}
		return result, flags
	}

	exponent := value >> uint(fraction) & (uint64(1)<<uint(exponentBits) - 1)
	mantissa := value & (uint64(1)<<uint(fraction) - 1)
	negative := value&floatSign != 0
	if exponent == uint64(1)<<uint(exponentBits)-1 && mantissa != 0 {
		return 0, 1 // Both signaling and quiet NaNs are invalid integer inputs.
	}
	flush := control&(1<<24) != 0
	if fixture.floatBits == 16 {
		flush = control&(1<<19) != 0 // FZ16 is separate from FZ.
	}
	if exponent == 0 && mantissa != 0 && flush {
		if fixture.floatBits == 16 {
			return 0, 0 // Arm FPCR.FZ16 never generates Input Denormal.
		}
		return 0, 0x80
	}
	var number float64
	if fixture.floatBits == 64 {
		number = math.Float64frombits(value)
	} else if fixture.floatBits == 32 {
		number = float64(math.Float32frombits(uint32(value)))
	} else {
		if exponent == 31 {
			number = math.Inf(1)
		} else if exponent == 0 {
			number = math.Ldexp(float64(mantissa), -24)
		} else {
			number = math.Ldexp(float64(1024+mantissa), int(exponent)-25)
		}
		if negative {
			number = -number
		}
	}
	rounded := math.Trunc(number)
	switch fixture.rounding {
	case 0:
		rounded = math.RoundToEven(number)
	case 1:
		rounded = math.Round(number)
	case 2:
		rounded = math.Ceil(number)
	case 3:
		rounded = math.Floor(number)
	}
	limit := math.Ldexp(1, fixture.integerBits-1)
	if fixture.unsigned {
		limit *= 2
		if rounded < 0 {
			return 0, 1
		}
		if rounded >= limit {
			return integerMask, 1
		}
	} else {
		if rounded < -limit {
			return uint64(1) << uint(fixture.integerBits-1), 1
		}
		if rounded >= limit {
			return uint64(1)<<uint(fixture.integerBits-1) - 1, 1
		}
	}
	flags := uint64(0)
	if rounded != number {
		flags = 0x10
	}
	if fixture.unsigned {
		return uint64(rounded) & integerMask, flags
	}
	return uint64(int64(rounded)) & integerMask, flags
}

func arm64ScalarConversionExceptionalValues(fixture arm64ScalarConversionFixture) []uint64 {
	if fixture.toFloat {
		mask := ^uint64(0) >> uint(64-fixture.integerBits)
		return []uint64{0, 1, mask, mask - 1, 1 << uint(fixture.integerBits-1),
			1<<uint(fixture.integerBits-1) - 1, 2049, 4095, 65504, 65519, 65520, 65535,
			1<<24 - 1, 1<<24 + 1, 1<<24 + 3, 1<<53 - 1, 1<<53 + 1, 1<<53 + 3}
	}
	var values []uint64
	switch fixture.floatBits {
	case 16:
		values = []uint64{0, 1, 0x3ff, 0x400, 0x3e00, 0x4300, 0x7800, 0x7bff, 0x7c00, 0x7e01, 0x7c01}
	case 32:
		values = []uint64{0, 1, 0x7fffff, 0x800000, 0x3fc00000, 0x40600000, 0x4effffff,
			0x4f000000, 0x4f7fffff, 0x4f800000, 0x5effffff, 0x5f000000, 0x5f7fffff, 0x5f800000,
			0x7f800000, 0x7fc00001, 0x7f800001}
	case 64:
		values = []uint64{0, 1, 0xfffffffffffff, 0x10000000000000, 0x3ff8000000000000,
			0x400c000000000000, 0x41dfffffffffffff, 0x41e0000000000000, 0x41efffffffffffff,
			0x41f0000000000000, 0x43dfffffffffffff, 0x43e0000000000000, 0x43efffffffffffff,
			0x43f0000000000000, 0x7ff0000000000000, 0x7ff8000000000001, 0x7ff0000000000001}
	}
	for _, value := range append([]uint64(nil), values...) {
		values = append(values, value|uint64(1)<<uint(fixture.floatBits-1))
	}
	return values
}

func TestCrossLinuxRuntimeMatrixARM64ScalarConversionExceptionalInputs(t *testing.T) {
	fixtures := arm64ScalarConversionFixtures()
	for _, fixture := range append([]arm64ScalarConversionFixture(nil), fixtures...) {
		fixture.dead = true
		fixtures = append(fixtures, fixture)
	}
	var rows []arm64ScalarConversionObservation
	for index, fixture := range fixtures {
		for _, value := range arm64ScalarConversionExceptionalValues(fixture) {
			for rounding := 0; rounding < 4; rounding++ {
				for flush := 0; flush < 2; flush++ {
					for defaultNaN := 0; defaultNaN < 2; defaultNaN++ {
						control := uint64(rounding)<<22 | uint64(flush)<<24 | uint64(defaultNaN)<<25
						if fixture.floatBits == 16 && flush != 0 {
							control |= 1 << 19
						}
						row := arm64ScalarConversionKnownObservation(index, fixture, control)
						row.input[fixture.sourceWord()] = value
						copy(row.want[:66], row.input[:66])
						result, flags := arm64ScalarConversionReference(fixture, value, control)
						if !fixture.dead {
							word := fixture.resultWord()
							row.want[word] = result
							if fixture.toFloat || fixture.simd {
								row.want[word+1] = 0
							}
						}
						row.want[67] = row.input[67] | flags
						rows = append(rows, row)
					}
				}
			}
		}
	}
	runARM64ScalarConversionObservations(t, fixtures, rows)
}
