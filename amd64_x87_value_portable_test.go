package plan9asm

import (
	"fmt"
	"math"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

type x87PortableBits struct {
	significand  uint64
	signExponent uint16
}

func x87PortableScalarModule(t *testing.T) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	for _, bits := range []int{32, 64} {
		typ := "float"
		if bits == 64 {
			typ = "double"
		}
		fmt.Fprintf(&ir, "define void @widen%d(ptr %%out, i%d %%bits) {\n", bits, bits)
		fmt.Fprintf(&ir, "  %%input = bitcast i%d %%bits to %s\n", bits, typ)
		ctx := amd64Ctx{b: &ir}
		value, err := ctx.x87PortableFromFloat("%input", bits)
		if err != nil {
			t.Fatal(err)
		}
		significand, signExponent := ctx.partsX87(value)
		fmt.Fprintf(&ir, "  store i64 %s, ptr %%out, align 1\n", significand)
		ir.WriteString("  %high = getelementptr i8, ptr %out, i32 8\n")
		fmt.Fprintf(&ir, "  store i16 %s, ptr %%high, align 1\n  ret void\n}\n", signExponent)
		fmt.Fprintf(&ir, "define void @narrow%d(ptr %%out, i64 %%sig, i16 %%se, i16 %%cw) {\n", bits)
		ctx = amd64Ctx{b: &ir}
		value = ctx.packX87("%sig", "%se")
		floating, err := ctx.x87PortableToFloat(value, bits, "%cw")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&ir, "  %%bits = bitcast %s %s to i%d\n", typ, floating, bits)
		fmt.Fprintf(&ir, "  store i%d %%bits, ptr %%out, align 1\n  ret void\n}\n", bits)
	}
	return ir.String()
}

// The oracle widens a finite IEEE value with Go's arbitrary-precision binary
// arithmetic. It does not call the emitter or reuse its normalization steps.
func x87PortableWidenOracle(raw uint64, width int) x87PortableBits {
	sign := raw >> 63
	value := math.Float64frombits(raw)
	if width == 32 {
		sign = (raw >> 31) & 1
		value = float64(math.Float32frombits(uint32(raw)))
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		for _, observed := range x87PortableNativeLoads {
			if observed.width == width && observed.input == raw {
				return observed.want
			}
		}
		panic("special IEEE input requires an independent native load anchor")
	}
	if value == 0 {
		return x87PortableBits{0, uint16(sign << 15)}
	}
	exact := new(big.Float).SetPrec(128).SetFloat64(math.Abs(value))
	mantissa := new(big.Float).SetPrec(128)
	exponent := exact.MantExp(mantissa)
	mantissa.SetMantExp(mantissa, 64)
	significand, accuracy := mantissa.Uint64()
	if accuracy != big.Exact {
		panic("finite IEEE value did not widen exactly")
	}
	return x87PortableBits{significand, uint16(exponent-1+16383) | uint16(sign<<15)}
}

// Narrowing is specified independently as an exact rational divided by the
// destination's representable unit, followed by quotient/remainder rounding.
func x87PortableNarrowOracle(value x87PortableBits, width, rounding int) uint64 {
	precision, bias := 53, 1023
	if width == 32 {
		precision, bias = 24, 127
	}
	sign := uint64(value.signExponent>>15) << (width - 1)
	exponent := int(value.signExponent & 32767)
	infinity := uint64(2*bias+1) << (precision - 1)
	if exponent != 0 && value.significand>>63 == 0 {
		return uint64(1)<<(width-1) | infinity | uint64(1)<<(precision-2)
	}
	if exponent == 32767 {
		if value.significand == 1<<63 {
			return sign | infinity
		}
		return sign | infinity | (value.significand&math.MaxInt64)>>(64-precision) | uint64(1)<<(precision-2)
	}
	if value.significand == 0 {
		return sign
	}
	if exponent == 0 {
		exponent = 1
	}
	numerator := new(big.Int).SetUint64(value.significand)
	denominator := big.NewInt(1)
	unit := numerator.BitLen() - 1 + exponent - 16383 - 63 - (precision - 1)
	minimumUnit := 1 - bias - (precision - 1)
	if unit < minimumUnit {
		unit = minimumUnit
	}
	shift := exponent - 16383 - 63 - unit
	if shift >= 0 {
		numerator.Lsh(numerator, uint(shift))
	} else {
		denominator.Lsh(denominator, uint(-shift))
	}
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if remainder.Sign() != 0 {
		comparison := new(big.Int).Lsh(remainder, 1).Cmp(denominator)
		increment := rounding == 0 && (comparison > 0 || comparison == 0 && quotient.Bit(0) != 0) ||
			rounding == 1 && sign != 0 || rounding == 2 && sign == 0
		if increment {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	if quotient.Sign() == 0 {
		return sign
	}
	highest := unit + quotient.BitLen() - 1
	if highest > bias {
		if rounding == 0 || rounding == 1 && sign != 0 || rounding == 2 && sign == 0 {
			return sign | infinity
		}
		return sign | (infinity - 1)
	}
	if highest < 1-bias {
		return sign | quotient.Uint64()
	}
	normal := new(big.Int).Set(quotient)
	if offset := precision - quotient.BitLen(); offset >= 0 {
		normal.Lsh(normal, uint(offset))
	} else {
		normal.Rsh(normal, uint(-offset))
	}
	return sign | uint64(highest+bias)<<(precision-1) | normal.Uint64()&(uint64(1)<<(precision-1)-1)
}

func x87PortableScalarOracle(t *testing.T) string {
	t.Helper()
	var oracle strings.Builder
	oracle.WriteString(`#include <stdint.h>
#include <stdio.h>
extern void widen32(uint64_t*,uint32_t);
extern void widen64(uint64_t*,uint64_t);
extern void narrow32(uint64_t*,uint64_t,uint16_t,uint16_t);
extern void narrow64(uint64_t*,uint64_t,uint16_t,uint16_t);
int main(void) {
uint64_t out[3];
`)
	for _, width := range []int{32, 64} {
		inputs := []uint64{0, 1, 2, 0x7fffff, 0x800000, 0x3f800000, 0x3f800001, 0x7f7fffff, 0x7f800000, 0x7fc00001, 0x7f800001}
		if width == 64 {
			inputs = []uint64{0, 1, 2, 0xfffffffffffff, 0x10000000000000, 0x3ff0000000000000, 0x3ff0000000000001, 0x7fefffffffffffff, 0x7ff0000000000000, 0x7ff8000000000001, 0x7ff0000000000001}
		}
		state := uint64(0x3141592653589793)
		for sample := 0; sample < 64; sample++ {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			input := state
			if width == 32 {
				input = uint64(uint32(input))
			}
			inputs = append(inputs, input)
		}
		for _, input := range inputs {
			for _, sign := range []uint64{0, uint64(1) << (width - 1)} {
				raw := input ^ sign
				want := x87PortableWidenOracle(raw, width)
				fmt.Fprintf(&oracle, "out[0]=out[1]=0; out[2]=0xabcde; widen%d(out,UINT64_C(%d));\n", width, raw)
				fmt.Fprintf(&oracle, "if(out[0]!=UINT64_C(%d)||out[1]!=%d||out[2]!=0xabcde){fprintf(stderr,\"widen%d input=%%llx got=%%llx/%%llx\\n\",(unsigned long long)UINT64_C(%d),(unsigned long long)out[0],(unsigned long long)out[1]);return 1;}\n", want.significand, want.signExponent, width, raw)
			}
		}
		values := []x87PortableBits{
			{0, 0}, {1, 0}, {1 << 63, 0}, {1 << 63, 1},
			{1 << 63, 16383}, {1<<63 + 1, 16383}, {math.MaxUint64, 16383},
			{0xc90fdaa22168c235, 16384}, {math.MaxUint64, 32766},
			{1 << 63, 32767}, {0xc000000000000001, 32767}, {0x8000000000000001, 32767},
			{0, 16383}, {1, 16383},
		}
		bias, precision := 1023, 53
		if width == 32 {
			bias, precision = 127, 24
		}
		for _, exponent := range []int{16383 - bias - precision, 16383 - bias, 16384 - bias, 16383 + bias, 16384 + bias} {
			for _, significand := range []uint64{1 << 63, 1<<63 + 1, 0xc000000000000000, math.MaxUint64} {
				values = append(values, x87PortableBits{significand, uint16(exponent)})
			}
		}
		for _, value := range values {
			for _, sign := range []uint16{0, 0x8000} {
				value.signExponent ^= sign
				for rounding := 0; rounding < 4; rounding++ {
					want := x87PortableNarrowOracle(value, width, rounding)
					fmt.Fprintf(&oracle, "out[0]=out[1]=0;out[2]=0xabcde;narrow%d(out,UINT64_C(%d),%d,%d);\n", width, value.significand, value.signExponent, 0x37f|rounding<<10)
					fmt.Fprintf(&oracle, "if(out[0]!=UINT64_C(%d)||out[1]||out[2]!=0xabcde){fprintf(stderr,\"narrow%d sig=%%llx se=%%x rc=%d got=%%llx want=%%llx\\n\",(unsigned long long)UINT64_C(%d),%d,(unsigned long long)out[0],(unsigned long long)UINT64_C(%d));return 2;}\n", want, width, rounding, value.significand, value.signExponent, want)
				}
			}
		}
	}
	oracle.WriteString("return 0;\n}\n")
	return oracle.String()
}

func TestX87PortableScalarValueObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	ir := x87PortableScalarModule(t)
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "portable80.ll", "portable80.o", ir)
		})
	}
}

func TestCrossLinuxRuntimeMatrixX87PortableScalarConversions(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang are required")
	}
	ir, oracle := x87PortableScalarModule(t), x87PortableScalarOracle(t)
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-scalars", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, optimization)
		})
	}
}
