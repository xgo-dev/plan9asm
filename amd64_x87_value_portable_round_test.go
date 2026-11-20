package plan9asm

import (
	"fmt"
	"math"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

func x87PortableRoundModule(t *testing.T) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString("declare i64 @llvm.ctlz.i64(i64,i1)\ndefine void @round80(ptr %out,i64 %sig,i16 %se,i16 %cw){\n")
	ctx := amd64Ctx{b: &ir}
	value, err := ctx.x87PortableRound(ctx.packX87("%sig", "%se"), "%cw")
	if err != nil {
		t.Fatal(err)
	}
	significand, exponent := ctx.partsX87(value)
	fmt.Fprintf(&ir, "  store i64 %s,ptr %%out,align 1\n  %%high = getelementptr i8,ptr %%out,i32 8\n  store i16 %s,ptr %%high,align 1\n  ret void\n}\n", significand, exponent)
	return ir.String()
}

// Round the exact rational by an integer quotient/remainder, then encode that
// integer without using any producer normalization or native floating math.
func x87PortableRoundOracle(value x87PortableBits, rounding int) x87PortableBits {
	exact, finite := x87PortableRational(value)
	if !finite {
		panic("finite integer-round oracle received a special encoding")
	}
	negative := value.signExponent&0x8000 != 0
	numerator := new(big.Int).Abs(exact.Num())
	denominator := new(big.Int).Set(exact.Denom())
	integer, remainder := new(big.Int), new(big.Int)
	integer.QuoRem(numerator, denominator, remainder)
	if remainder.Sign() != 0 {
		order := new(big.Int).Lsh(remainder, 1).Cmp(denominator)
		increment := rounding == 0 && (order > 0 || order == 0 && integer.Bit(0) != 0) ||
			rounding == 1 && negative || rounding == 2 && !negative
		if increment {
			integer.Add(integer, big.NewInt(1))
		}
	}
	sign := value.signExponent & 0x8000
	if integer.Sign() == 0 {
		return x87PortableBits{0, sign}
	}
	highest := integer.BitLen() - 1
	stored := new(big.Int).Set(integer)
	if highest < 63 {
		stored.Lsh(stored, uint(63-highest))
	} else {
		stored.Rsh(stored, uint(highest-63))
	}
	return x87PortableBits{stored.Uint64(), sign | uint16(highest+16383)}
}

func x87PortableRoundOracleProgram() string {
	values := []x87PortableBits{
		{0, 0}, {1, 0}, {math.MaxUint64, 0}, {1 << 63, 1},
		{1 << 63, 16381}, {1 << 63, 16382}, {1<<63 + 1, 16382},
		{0xc000000000000000, 16383}, {0xa000000000000000, 16384},
		{math.MaxUint64, 16445}, {1 << 63, 16446},
		{math.MaxUint64, 16446}, {math.MaxUint64, 32766},
	}
	for _, row := range x87PortableObservedConstants {
		for _, significand := range row.significand {
			values = append(values, x87PortableBits{significand, row.exponent})
		}
	}
	var main strings.Builder
	main.WriteString("#include <stdint.h>\n#include <stdio.h>\nextern void round80(uint64_t*,uint64_t,uint16_t,uint16_t);\nint main(void){uint64_t out[3];\n")
	for _, original := range values {
		for _, sign := range []uint16{0, 0x8000} {
			value := original
			value.signExponent ^= sign
			for _, precision := range []uint16{0, 0x200, 0x300} {
				for rounding := 0; rounding < 4; rounding++ {
					want := x87PortableRoundOracle(value, rounding)
					word := uint16(0x7f) | precision | uint16(rounding)<<10
					fmt.Fprintf(&main, "out[0]=out[1]=0;out[2]=19;round80(out,UINT64_C(%d),%d,%d);if(out[0]!=UINT64_C(%d)||out[1]!=%d||out[2]!=19){fprintf(stderr,\"round80 input=%%llx/%%x cw=%%x got=%%llx/%%llx want=%%llx/%%x\\n\",(unsigned long long)UINT64_C(%d),%d,%d,(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)UINT64_C(%d),%d);return 1;}\n", value.significand, value.signExponent, word, want.significand, want.signExponent, value.significand, value.signExponent, word, want.significand, want.signExponent)
				}
			}
		}
	}
	main.WriteString("return 0;}\n")
	return main.String()
}

func TestX87PortableRoundObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	ir := x87PortableRoundModule(t)
	for _, target := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(target+"/"+level, func(t *testing.T) {
				x86PackedStringCompileObject(t, llc, target, ir, level)
			})
		}
	}
}

func TestCrossLinuxRuntimeMatrixX87PortableRoundFiniteValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang are required")
	}
	ir, oracle := x87PortableRoundModule(t), x87PortableRoundOracleProgram()
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-round", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, level)
		})
	}
}
