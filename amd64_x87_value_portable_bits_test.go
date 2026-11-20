package plan9asm

import (
	"fmt"
	"math"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

var x87PortableObservedConstants = []struct {
	op          Op
	exponent    uint16
	significand [4]uint64
}{
	{"FLDZ", 0, [4]uint64{0, 0, 0, 0}},
	{"FLD1", 0x3fff, [4]uint64{0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0x8000000000000000}},
	{"FLDPI", 0x4000, [4]uint64{0xc90fdaa22168c235, 0xc90fdaa22168c234, 0xc90fdaa22168c235, 0xc90fdaa22168c234}},
	{"FLDL2E", 0x3fff, [4]uint64{0xb8aa3b295c17f0bc, 0xb8aa3b295c17f0bb, 0xb8aa3b295c17f0bc, 0xb8aa3b295c17f0bb}},
	{"FLDL2T", 0x4000, [4]uint64{0xd49a784bcd1b8afe, 0xd49a784bcd1b8afe, 0xd49a784bcd1b8aff, 0xd49a784bcd1b8afe}},
	{"FLDLG2", 0x3ffd, [4]uint64{0x9a209a84fbcff799, 0x9a209a84fbcff798, 0x9a209a84fbcff799, 0x9a209a84fbcff798}},
	{"FLDLN2", 0x3ffe, [4]uint64{0xb17217f7d1cf79ac, 0xb17217f7d1cf79ab, 0xb17217f7d1cf79ac, 0xb17217f7d1cf79ab}},
}

func TestX87PortableValueWidthContracts(t *testing.T) {
	for _, width := range []int{0, 8, 80, 128} {
		var ir strings.Builder
		ctx := amd64Ctx{b: &ir}
		if _, err := ctx.x87PortableFromFloat("%value", width); err == nil {
			t.Fatalf("accepted IEEE input width %d", width)
		}
		if _, err := ctx.x87PortableToFloat(x87ZeroValue, width, "%cw"); err == nil {
			t.Fatalf("accepted IEEE result width %d", width)
		}
		if _, err := ctx.x87PortableFromSigned("%value", width); err == nil {
			t.Fatalf("accepted signed input width %d", width)
		}
		if _, err := ctx.x87PortableToSigned(x87ZeroValue, width, "%cw"); err == nil {
			t.Fatalf("accepted signed result width %d", width)
		}
		if ir.Len() != 0 {
			t.Fatal("invalid width emitted a partial numerical conversion")
		}
	}
	var ir strings.Builder
	ctx := amd64Ctx{b: &ir}
	if _, err := ctx.x87PortableConstant("FLD2", "%cw"); err == nil || ir.Len() != 0 {
		t.Fatal("unknown constant acquired a numerical value", err)
	}
}

func x87PortableValueModule(t *testing.T) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString(x87PortableScalarModule(t))
	for _, bits := range []int{16, 32, 64} {
		fmt.Fprintf(&ir, "define void @integer_in%d(ptr %%out, i%d %%value) {\n", bits, bits)
		ctx := amd64Ctx{b: &ir}
		value, err := ctx.x87PortableFromSigned("%value", bits)
		if err != nil {
			t.Fatal(err)
		}
		significand, signExponent := ctx.partsX87(value)
		fmt.Fprintf(&ir, "  store i64 %s, ptr %%out, align 1\n", significand)
		ir.WriteString("  %high = getelementptr i8, ptr %out, i32 8\n")
		fmt.Fprintf(&ir, "  store i16 %s, ptr %%high, align 1\n  ret void\n}\n", signExponent)
		fmt.Fprintf(&ir, "define void @integer_out%d(ptr %%out, i64 %%sig, i16 %%se, i16 %%cw) {\n", bits)
		ctx = amd64Ctx{b: &ir}
		value = ctx.packX87("%sig", "%se")
		integer, err := ctx.x87PortableToSigned(value, bits, "%cw")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&ir, "  store i%d %s, ptr %%out, align 1\n  ret void\n}\n", bits, integer)
	}
	for _, constant := range x87PortableObservedConstants {
		fmt.Fprintf(&ir, "define void @constant_%s(ptr %%out, i16 %%cw) {\n", constant.op)
		ctx := amd64Ctx{b: &ir}
		value, err := ctx.x87PortableConstant(constant.op, "%cw")
		if err != nil {
			t.Fatal(err)
		}
		significand, signExponent := ctx.partsX87(value)
		fmt.Fprintf(&ir, "  store i64 %s, ptr %%out, align 1\n", significand)
		ir.WriteString("  %high = getelementptr i8, ptr %out, i32 8\n")
		fmt.Fprintf(&ir, "  store i16 %s, ptr %%high, align 1\n  ret void\n}\n", signExponent)
	}
	ir.WriteString("define void @compare80(ptr %out, i64 %a, i16 %ae, i64 %b, i16 %be) {\n")
	ctx := amd64Ctx{b: &ir}
	left, right := ctx.packX87("%a", "%ae"), ctx.packX87("%b", "%be")
	equal, less, unordered := ctx.x87PortableCompare(left, right)
	equal = ctx.x87PortableIR("select i1 %s, i16 2, i16 0", equal)
	less = ctx.x87PortableIR("select i1 %s, i16 1, i16 0", less)
	unordered = ctx.x87PortableIR("select i1 %s, i16 4, i16 0", unordered)
	result := ctx.x87PortableIR("or i16 %s, %s", equal, less)
	result = ctx.x87PortableIR("or i16 %s, %s", result, unordered)
	fmt.Fprintf(&ir, "  store i16 %s, ptr %%out, align 1\n  ret void\n}\n", result)
	ir.WriteString("define void @classify80(ptr %out, i64 %a, i16 %ae) {\n")
	ctx = amd64Ctx{b: &ir}
	result = ctx.x87PortableClassify(ctx.packX87("%a", "%ae"))
	fmt.Fprintf(&ir, "  store i16 %s, ptr %%out, align 1\n  ret void\n}\n", result)
	return ir.String()
}

func x87PortableRational(value x87PortableBits) (*big.Rat, bool) {
	exponent := int(value.signExponent & 32767)
	if exponent == 32767 || exponent != 0 && value.significand>>63 == 0 {
		return nil, false
	}
	if exponent == 0 {
		exponent = 1
	}
	numerator := new(big.Int).SetUint64(value.significand)
	denominator := big.NewInt(1)
	if shift := exponent - 16383 - 63; shift >= 0 {
		numerator.Lsh(numerator, uint(shift))
	} else {
		denominator.Lsh(denominator, uint(-shift))
	}
	if value.signExponent&0x8000 != 0 {
		numerator.Neg(numerator)
	}
	return new(big.Rat).SetFrac(numerator, denominator), true
}

func x87PortableSignedOracle(value x87PortableBits, width, rounding int) uint64 {
	indefinite := uint64(1) << (width - 1)
	exact, valid := x87PortableRational(value)
	if !valid {
		return indefinite
	}
	negative := exact.Sign() < 0
	numerator := new(big.Int).Abs(exact.Num())
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, exact.Denom(), remainder)
	if remainder.Sign() != 0 {
		comparison := new(big.Int).Lsh(remainder, 1).Cmp(exact.Denom())
		increment := rounding == 0 && (comparison > 0 || comparison == 0 && quotient.Bit(0) != 0) ||
			rounding == 1 && negative || rounding == 2 && !negative
		if increment {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	if negative {
		quotient.Neg(quotient)
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(width-1))
	minimum := new(big.Int).Neg(limit)
	if quotient.Cmp(minimum) < 0 || quotient.Cmp(limit) >= 0 {
		return indefinite
	}
	result := uint64(quotient.Int64())
	if width != 64 {
		result &= uint64(1)<<width - 1
	}
	return result
}

func x87PortableValueOracle(t *testing.T) string {
	t.Helper()
	var c strings.Builder
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for _, width := range []int{16, 32, 64} {
		fmt.Fprintf(&c, "extern void integer_in%d(uint64_t*,int%d_t);\n", width, width)
		fmt.Fprintf(&c, "extern void integer_out%d(uint64_t*,uint64_t,uint16_t,uint16_t);\n", width)
	}
	for _, constant := range x87PortableObservedConstants {
		fmt.Fprintf(&c, "extern void constant_%s(uint64_t*,uint16_t);\n", constant.op)
	}
	c.WriteString("extern void compare80(uint64_t*,uint64_t,uint16_t,uint64_t,uint16_t);\n")
	c.WriteString("extern void classify80(uint64_t*,uint64_t,uint16_t);\nint main(void){uint64_t out[3];\n")
	for _, width := range []int{16, 32, 64} {
		inputs := []int64{0, 1, -1, 2, -2, 127, -128, 32767, -32768}
		if width >= 32 {
			inputs = append(inputs, math.MaxInt32, math.MinInt32)
		}
		if width == 64 {
			inputs = append(inputs, 1<<53-1, 1<<53+1, -(1<<53 + 1), math.MaxInt64, math.MinInt64)
		}
		for _, input := range inputs {
			magnitude := new(big.Int).Abs(big.NewInt(input))
			want := x87PortableBits{}
			if magnitude.Sign() != 0 {
				want.signExponent = uint16(magnitude.BitLen() - 1 + 16383)
				want.significand = new(big.Int).Lsh(magnitude, uint(64-magnitude.BitLen())).Uint64()
				if input < 0 {
					want.signExponent |= 0x8000
				}
			}
			fmt.Fprintf(&c, "out[0]=out[1]=0;out[2]=19;integer_in%d(out,(int%d_t)UINT64_C(%d));\n", width, width, uint64(input))
			fmt.Fprintf(&c, "if(out[0]!=UINT64_C(%d)||out[1]!=%d||out[2]!=19)return 10;\n", want.significand, want.signExponent)
		}
		values := []x87PortableBits{{0, 0}, {1, 0}, {1 << 63, 0}, {1 << 63, 16382}, {0xc000000000000000, 16383}, {0xa000000000000000, 16384}, {math.MaxUint64, uint16(16383 + width - 2)}, {math.MaxUint64 - 1, uint16(16383 + width - 2)}, {1 << 63, uint16(16383 + width - 1)}, {1<<63 + 1, uint16(16383 + width - 1)}, {1 << 63, 32767}, {0xc000000000000000, 32767}, {1, 16383}}
		for _, value := range values {
			for _, sign := range []uint16{0, 0x8000} {
				value.signExponent ^= sign
				for rounding := 0; rounding < 4; rounding++ {
					want := x87PortableSignedOracle(value, width, rounding)
					fmt.Fprintf(&c, "out[0]=out[1]=0;out[2]=19;integer_out%d(out,UINT64_C(%d),%d,%d);\n", width, value.significand, value.signExponent, 0x37f|rounding<<10)
					fmt.Fprintf(&c, "if(out[0]!=UINT64_C(%d)||out[1]||out[2]!=19){fprintf(stderr,\"integer%d sig=%%llx se=%%x rc=%d got=%%llx want=%%llx\\n\",(unsigned long long)UINT64_C(%d),%d,(unsigned long long)out[0],(unsigned long long)UINT64_C(%d));return 11;}\n", want, width, rounding, value.significand, value.signExponent, want)
				}
			}
		}
	}
	// These complete four-RC rows come from independent original x87 kernels,
	// observed with current and minimum Go assemblers. PC does not round FLD.
	for _, constant := range x87PortableObservedConstants {
		for rounding, significand := range constant.significand {
			for _, precision := range []int{0, 0x200, 0x300} {
				fmt.Fprintf(&c, "out[0]=out[1]=0;out[2]=19;constant_%s(out,%d);\n", constant.op, 0x7f|precision|rounding<<10)
				fmt.Fprintf(&c, "if(out[0]!=UINT64_C(%d)||out[1]!=%d||out[2]!=19)return 12;\n", significand, constant.exponent)
			}
		}
	}
	values := []struct {
		bits  x87PortableBits
		class uint16
	}{
		{x87PortableBits{0, 0}, 0x4000},
		{x87PortableBits{1, 0}, 0x4400},
		{x87PortableBits{1 << 63, 0}, 0x400},
		{x87PortableBits{1 << 63, 1}, 0x400},
		{x87PortableBits{1 << 63, 16383}, 0x400},
		{x87PortableBits{1<<63 + 1, 16383}, 0x400},
		{x87PortableBits{0xc90fdaa22168c235, 16384}, 0x400},
		{x87PortableBits{1 << 63, 32767}, 0x500},
		{x87PortableBits{0xc000000000000001, 32767}, 0x100},
		{x87PortableBits{0x8000000000000001, 32767}, 0x100},
		{x87PortableBits{1, 16383}, 0},
	}
	for _, left := range values {
		for _, leftSign := range []uint16{0, 0x8000} {
			left.bits.signExponent ^= leftSign
			fmt.Fprintf(&c, "out[0]=out[1]=0;out[2]=19;classify80(out,UINT64_C(%d),%d);if(out[0]!=%d||out[1]||out[2]!=19)return 13;\n", left.bits.significand, left.bits.signExponent, left.class|leftSign>>6)
			for _, right := range values {
				for _, rightSign := range []uint16{0, 0x8000} {
					right.bits.signExponent ^= rightSign
					want := x87PortableComparisonOracle(left.bits, right.bits)
					fmt.Fprintf(&c, "out[0]=out[1]=0;out[2]=19;compare80(out,UINT64_C(%d),%d,UINT64_C(%d),%d);if(out[0]!=%d||out[1]||out[2]!=19)return 14;\n", left.bits.significand, left.bits.signExponent, right.bits.significand, right.bits.signExponent, want)
				}
			}
		}
	}
	c.WriteString("return 0;}\n")
	return c.String()
}

func x87PortableComparisonOracle(left, right x87PortableBits) int {
	first, firstFinite := x87PortableRational(left)
	second, secondFinite := x87PortableRational(right)
	if !firstFinite || !secondFinite {
		infinite := func(value x87PortableBits) int {
			if value.signExponent&32767 == 32767 && value.significand == 1<<63 {
				if value.signExponent&0x8000 != 0 {
					return -1
				}
				return 1
			}
			return 0
		}
		a, b := infinite(left), infinite(right)
		if !firstFinite && a == 0 || !secondFinite && b == 0 {
			return 4
		}
		if a == b {
			return 2
		}
		if a < b {
			return 1
		}
		return 0
	}
	if order := first.Cmp(second); order == 0 {
		return 2
	} else if order < 0 {
		return 1
	}
	return 0
}

func TestX87PortableValueFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "portable80-values.ll", "portable80-values.o", x87PortableValueModule(t))
		})
	}
}

func TestCrossLinuxRuntimeMatrixX87PortableValueFamily(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang are required")
	}
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-values", testTargetTriple(runtime.GOOS, runtime.GOARCH), x87PortableValueModule(t), x87PortableValueOracle(t), nil, optimization)
		})
	}
}
