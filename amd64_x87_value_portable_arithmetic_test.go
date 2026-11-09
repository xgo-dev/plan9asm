package plan9asm

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func x87PortableArithmeticModule(t *testing.T) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\n")
	for _, operation := range []string{"fadd", "fsub", "fmul", "fdiv"} {
		fmt.Fprintf(&ir, "define void @binary_%s(ptr %%out, i64 %%a, i16 %%ae, i64 %%b, i16 %%be, i16 %%cw) {\n", operation)
		ctx := amd64Ctx{b: &ir}
		left, right := ctx.packX87("%a", "%ae"), ctx.packX87("%b", "%be")
		value, err := ctx.x87PortableBinary(operation, left, right, "%cw")
		if err != nil {
			t.Fatal(err)
		}
		significand, exponent := ctx.partsX87(value)
		fmt.Fprintf(&ir, "  store i64 %s, ptr %%out, align 1\n", significand)
		ir.WriteString("  %high = getelementptr i8, ptr %out, i32 8\n")
		fmt.Fprintf(&ir, "  store i16 %s, ptr %%high, align 1\n  ret void\n}\n", exponent)
	}
	return ir.String()
}

// This oracle rounds an exact rational onto a precision-dependent binary80
// grid. No producer helper or host floating arithmetic computes the answer.
func x87PortableArithmeticOracle(operation string, left, right x87PortableBits, precision, rounding int) x87PortableBits {
	a, validA := x87PortableRational(left)
	b, validB := x87PortableRational(right)
	if !validA || !validB || operation == "fdiv" && b.Sign() == 0 {
		panic("finite arithmetic oracle received a special or zero divisor")
	}
	exact := new(big.Rat)
	switch operation {
	case "fadd":
		exact.Add(a, b)
	case "fsub":
		exact.Sub(a, b)
	case "fmul":
		exact.Mul(a, b)
	case "fdiv":
		exact.Quo(a, b)
	default:
		panic("unknown arithmetic oracle operation")
	}
	negative := exact.Sign() < 0
	if exact.Sign() == 0 {
		negative = (left.signExponent^right.signExponent)&0x8000 != 0
		if operation == "fadd" || operation == "fsub" {
			first := left.signExponent&0x8000 != 0
			second := right.signExponent&0x8000 != 0
			if operation == "fsub" {
				second = !second
			}
			negative = rounding == 1
			if first == second {
				negative = first
			}
		}
	}
	sign := uint16(0)
	if negative {
		sign = 0x8000
	}
	if exact.Sign() == 0 {
		return x87PortableBits{0, sign}
	}
	numerator := new(big.Int).Abs(exact.Num())
	denominator := new(big.Int).Set(exact.Denom())
	highest := numerator.BitLen() - denominator.BitLen()
	if highest >= 0 {
		if numerator.Cmp(new(big.Int).Lsh(new(big.Int).Set(denominator), uint(highest))) < 0 {
			highest--
		}
	} else if new(big.Int).Lsh(new(big.Int).Set(numerator), uint(-highest)).Cmp(denominator) < 0 {
		highest--
	}
	unit := highest - precision + 1
	if minimum := -16381 - precision; unit < minimum {
		unit = minimum
	}
	if unit < 0 {
		numerator.Lsh(numerator, uint(-unit))
	} else {
		denominator.Lsh(denominator, uint(unit))
	}
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if remainder.Sign() != 0 {
		comparison := new(big.Int).Lsh(remainder, 1).Cmp(denominator)
		increment := rounding == 0 && (comparison > 0 || comparison == 0 && quotient.Bit(0) != 0) ||
			rounding == 1 && negative || rounding == 2 && !negative
		if increment {
			quotient.Add(quotient, big.NewInt(1))
		}
	}
	if quotient.Sign() == 0 {
		return x87PortableBits{0, sign}
	}
	highest = unit + quotient.BitLen() - 1
	if highest > 16383 {
		if rounding == 0 || rounding == 1 && negative || rounding == 2 && !negative {
			return x87PortableBits{1 << 63, sign | 32767}
		}
		maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(precision)), big.NewInt(1))
		maximum.Lsh(maximum, uint(64-precision))
		return x87PortableBits{maximum.Uint64(), sign | 32766}
	}
	if highest < -16382 {
		return x87PortableBits{new(big.Int).Lsh(quotient, uint(unit+16445)).Uint64(), sign}
	}
	stored := new(big.Int).Set(quotient)
	if shift := 64 - quotient.BitLen(); shift >= 0 {
		stored.Lsh(stored, uint(shift))
	} else {
		stored.Rsh(stored, uint(-shift))
	}
	return x87PortableBits{stored.Uint64(), sign | uint16(highest+16383)}
}

func x87PortableArithmeticOracleProgram(t *testing.T) string {
	t.Helper()
	type pair struct{ left, right x87PortableBits }
	one := x87PortableBits{1 << 63, 16383}
	minusOne := x87PortableBits{1 << 63, 0xbfff}
	two := x87PortableBits{1 << 63, 16384}
	three := x87PortableBits{0xc000000000000000, 16384}
	oneUp := x87PortableBits{1<<63 + 1, 16383}
	belowOne := x87PortableBits{math.MaxUint64, 16382}
	minimumNormal := x87PortableBits{1 << 63, 1}
	minimum := x87PortableBits{1, 0}
	maximum := x87PortableBits{math.MaxUint64, 32766}
	pairs := []pair{
		{one, one}, {one, minusOne}, {one, oneUp}, {oneUp, belowOne},
		{one, three}, {three, oneUp}, {minimumNormal, oneUp},
		{minimum, two}, {maximum, oneUp}, {maximum, minimum},
		{x87PortableBits{0, 0}, one}, {x87PortableBits{0, 0x8000}, minusOne},
		{x87PortableBits{0x8000000000000400, 16436}, x87PortableBits{1 << 63, 0xc034}},
	}
	for _, distance := range []uint16{24, 53, 64, 128} {
		pairs = append(pairs, pair{one, x87PortableBits{1 << 63, 16383 - distance}})
	}
	state := uint64(0x90e3ca4872311d5f)
	for sample := 0; sample < 32; sample++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		left := x87PortableBits{state | 1<<63, uint16(16352 + sample)}
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		right := x87PortableBits{state | 1<<63, uint16(16375 + sample%13)}
		if sample&1 != 0 {
			left.signExponent |= 0x8000
		}
		if sample&2 != 0 {
			right.signExponent |= 0x8000
		}
		pairs = append(pairs, pair{left, right})
	}
	var c strings.Builder
	c.WriteString(`#include <stdint.h>
#include <stdio.h>
typedef void (*binary)(uint64_t*,uint64_t,uint16_t,uint64_t,uint16_t,uint16_t);
`)
	operations := []string{"fadd", "fsub", "fmul", "fdiv"}
	for _, operation := range operations {
		fmt.Fprintf(&c, "extern void binary_%s(uint64_t*,uint64_t,uint16_t,uint64_t,uint16_t,uint16_t);\n", operation)
	}
	c.WriteString("static binary operations[]={binary_fadd,binary_fsub,binary_fmul,binary_fdiv};\n")
	c.WriteString("struct row {unsigned op;uint64_t a;uint16_t ae;uint64_t b;uint16_t be;uint16_t cw;uint64_t want;uint16_t we;};\nstatic struct row rows[]={\n")
	for index, operation := range operations {
		for _, input := range pairs {
			for _, sign := range []uint16{0, 0x8000} {
				input.left.signExponent ^= sign
				for _, precision := range []int{24, 53, 64} {
					pc := map[int]int{24: 0, 53: 0x200, 64: 0x300}[precision]
					for rounding := 0; rounding < 4; rounding++ {
						want := x87PortableArithmeticOracle(operation, input.left, input.right, precision, rounding)
						fmt.Fprintf(&c, "{%d,UINT64_C(%d),%d,UINT64_C(%d),%d,%d,UINT64_C(%d),%d},\n",
							index, input.left.significand, input.left.signExponent,
							input.right.significand, input.right.signExponent, 0x7f|pc|rounding<<10,
							want.significand, want.signExponent)
					}
				}
			}
		}
	}
	c.WriteString(`};
int main(void) {
    for (unsigned index=0;index<sizeof(rows)/sizeof(rows[0]);index++) {
        struct row r=rows[index];
        uint64_t out[3]={0,0,19};
        operations[r.op](out,r.a,r.ae,r.b,r.be,r.cw);
        if(out[0]!=r.want||out[1]!=r.we||out[2]!=19) {
            fprintf(stderr,"binary row=%u op=%u a=%llx/%x b=%llx/%x cw=%x got=%llx/%llx want=%llx/%x\n",
                index,r.op,(unsigned long long)r.a,r.ae,(unsigned long long)r.b,r.be,r.cw,
                (unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)r.want,r.we);
            return 1;
        }
    }
    return 0;
}
`)
	return c.String()
}

func TestX87PortableArithmeticObjects(t *testing.T) {
	var rejected strings.Builder
	ctx := amd64Ctx{b: &rejected}
	if _, err := ctx.x87PortableBinary("frem", x87ZeroValue, x87ZeroValue, "895"); err == nil || rejected.Len() != 0 {
		t.Fatal("an unknown arithmetic operation must fail before emitting IR")
	}
	llc, nm := findLLVM22Tool("llc"), findLLVM22Tool("llvm-nm")
	if llc == "" || nm == "" {
		t.Fatal("LLVM 22 llc/llvm-nm are required")
	}
	ir := x87PortableArithmeticModule(t)
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			for _, optimization := range []int{0, 2} {
				t.Run(fmt.Sprintf("backend%d", optimization), func(t *testing.T) {
					directory := t.TempDir()
					input := filepath.Join(directory, "portable80-arithmetic.ll")
					object := filepath.Join(directory, "portable80-arithmetic.o")
					if err := os.WriteFile(input, []byte(ir), 0644); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := runtimeOracleStageContext(t)
					command := exec.CommandContext(ctx, llc, fmt.Sprintf("-O=%d", optimization), "-mtriple="+triple, "-filetype=obj", input, "-o", object)
					output, err := runtimeOracleCombinedOutput(ctx, command)
					cancel()
					if err != nil {
						t.Fatalf("LLVM object failed: %v\n%s", err, output)
					}
					ctx, cancel = runtimeOracleStageContext(t)
					output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, nm, "--undefined-only", object))
					cancel()
					if err != nil {
						t.Fatalf("LLVM undefined-symbol inventory failed: %v\n%s", err, output)
					}
					// Object production does not certify a link or runtime. Preserve
					// exact helper requirements instead of silently assuming none.
					t.Logf("undefined symbols:\n%s", output)
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX87PortableArithmetic(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang are required")
	}
	ir, oracle := x87PortableArithmeticModule(t), x87PortableArithmeticOracleProgram(t)
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-arithmetic", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, optimization)
		})
	}
}
