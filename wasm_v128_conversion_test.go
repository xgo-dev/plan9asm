package plan9asm

import (
	"math"
	"strings"
)

type wasmV128ConversionTestForm struct {
	name                    string
	inputBits, outputBits   int
	lanes                   int
	inputFloat, outputFloat bool
}

var wasmV128ConversionTestForms = [...]wasmV128ConversionTestForm{
	{"F32x4ConvertI32x4S", 32, 32, 4, false, true},
	{"F32x4ConvertI32x4U", 32, 32, 4, false, true},
	{"F64x2ConvertLowI32x4S", 32, 64, 2, false, true},
	{"F64x2ConvertLowI32x4U", 32, 64, 2, false, true},
	{"F32x4DemoteF64x2Zero", 64, 32, 2, true, true},
	{"F64x2PromoteLowF32x4", 32, 64, 2, true, true},
	{"I32x4TruncSatF32x4S", 32, 32, 4, true, false},
	{"I32x4TruncSatF32x4U", 32, 32, 4, true, false},
	{"I32x4TruncSatF64x2SZero", 64, 32, 2, true, false},
	{"I32x4TruncSatF64x2UZero", 64, 32, 2, true, false},
	{"I32x4RelaxedTruncF32x4S", 32, 32, 4, true, false},
	{"I32x4RelaxedTruncF32x4U", 32, 32, 4, true, false},
	{"I32x4RelaxedTruncF64x2S", 64, 32, 2, true, false},
	{"I32x4RelaxedTruncF64x2U", 64, 32, 2, true, false},
}

func wasmV128ConversionTestLookup(name string) (wasmV128ConversionTestForm, bool) {
	for _, form := range wasmV128ConversionTestForms {
		if name == form.name {
			return form, true
		}
	}
	return wasmV128ConversionTestForm{}, false
}

func (form wasmV128ConversionTestForm) inputs() [][2]uint64 {
	var samples []uint64
	if form.inputFloat {
		samples = wasmFloatBinarySamples(form.inputBits)
		for _, number := range []float64{
			-0.875, 1.875, -2147483648.75, -2147483647.75, 2147483647.75,
			2147483648, 4294967295.75, 4294967296, 1 + 0x1p-24, 0x1.fffffep-127,
		} {
			raw := math.Float64bits(number)
			if form.inputBits == 32 {
				raw = uint64(math.Float32bits(float32(number)))
			}
			samples = append(samples, raw)
		}
	} else {
		samples = []uint64{
			0, 1, 2, 0xffffffff, 0xfffffffe, 0x80000000, 0x80000001,
			0x7fffffff, 0x7ffffffe, 0x7fffff80, 0x80000080, 0xffff0000,
			0xfeffffff, 0x10000, 0xfffe, 0xffff, 0x10001, 0x12345678, 0x87654321,
			0xffffff, 0x1000000, 0x1000001, 0x1000002, 0x1000003,
			0xff000001, 0xff000002, 0xfeffffff, 0x00fffffe, 0x7fffff81, 0x8000007f,
		}
	}
	inputs := make([][2]uint64, len(samples))
	for i := range inputs {
		for lane := 0; lane < 128/form.inputBits; lane++ {
			offset := lane * form.inputBits
			inputs[i][offset/64] |= samples[(i+7*lane)%len(samples)] << (offset % 64)
		}
	}
	return inputs
}

func (form wasmV128ConversionTestForm) reference(input [2]uint64, original bool) (want, mask [2]uint64) {
	mask = [2]uint64{^uint64(0), ^uint64(0)}
	inputMask := uint64(1)<<form.inputBits - 1
	signed := strings.HasSuffix(form.name, "S") || strings.HasSuffix(form.name, "SZero")
	allowRelaxed := original && strings.Contains(form.name, "RelaxedTrunc")
	for lane := 0; lane < form.lanes; lane++ {
		inputOffset := lane * form.inputBits
		raw := (input[inputOffset/64] >> (inputOffset % 64)) & inputMask
		outputOffset := lane * form.outputBits
		half, shift := outputOffset/64, outputOffset%64

		var number float64
		switch {
		case form.inputFloat && form.inputBits == 32:
			number = float64(math.Float32frombits(uint32(raw)))
		case form.inputFloat:
			number = math.Float64frombits(raw)
		case signed:
			number = float64(int32(raw))
		default:
			number = float64(uint32(raw))
		}
		switch {
		case !form.outputFloat:
			if allowRelaxed && wasmV128RelaxedTruncUnspecified(number, signed) {
				mask[half] &^= uint64(0xffffffff) << shift
				continue
			}
			want[half] |= uint64(wasmV128SaturatingI32Reference(number, signed)) << shift
		case math.IsNaN(number):
			exponent, quiet := uint64(0x7ff0000000000000), uint64(1)<<51
			if form.outputBits == 32 {
				exponent, quiet = 0x7f800000, 1<<22
			}
			want[half] |= (exponent | quiet) << shift
			inputCanonical := uint64(0x7ff8000000000000)
			if form.inputBits == 32 {
				inputCanonical = 0x7fc00000
			}
			if raw&(inputMask>>1) == inputCanonical {
				mask[half] &^= uint64(1) << (shift + form.outputBits - 1)
			} else {
				outputMask := uint64(1)<<form.outputBits - 1
				mask[half] &^= (outputMask &^ (exponent | quiet)) << shift
			}
		case form.outputBits == 32:
			want[half] |= uint64(math.Float32bits(float32(number))) << shift
		default:
			want[half] = math.Float64bits(number)
		}
	}
	return want, mask
}

func (form wasmV128ConversionTestForm) comparisonBody(input [2]uint64) string {
	expected, mask := form.reference(input, false)
	return wasmV128CoreConstant(input) + form.name + "\n" +
		wasmV128CoreConstant(mask) + "V128And\n" +
		wasmV128CoreConstant(expected) + "V128Xor\nV128AnyTrue\n"
}

func wasmV128RelaxedTruncUnspecified(number float64, signed bool) bool {
	result := math.Trunc(number)
	if signed {
		return !(result >= -2147483648 && result < 2147483648)
	}
	return !(result >= 0 && result < 4294967296)
}

func wasmV128SaturatingI32Reference(number float64, signed bool) uint32 {
	low, high := 0.0, 4294967295.0
	if signed {
		low, high = -2147483648, 2147483647
	}
	switch {
	case math.IsNaN(number):
		number = 0
	case number < low:
		number = low
	case number > high:
		number = high
	}
	return uint32(int64(number))
}
