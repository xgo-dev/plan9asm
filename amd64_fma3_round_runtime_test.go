package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This separately exercises the production numerical helper on every host.
// Original instruction acceptance and caller/LLVM objects are independently
// covered by the complete Go-format oracle, not inferred from this helper.
func TestCrossLinuxRuntimeMatrixX86FMA3FixedRoundingExtremes(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var ir strings.Builder
	ir.WriteString("declare i128 @llvm.ctlz.i128(i128, i1)\n")
	for _, bits := range []int{32, 64} {
		floatType := amd64FMA3LLVMType(1, bits)
		fmt.Fprintf(&ir, "declare %s @llvm.fma.f%d(%s, %s, %s)\n", floatType, bits, floatType, floatType, floatType)
		emitAMD64FMA3RoundingHelper(&ir, bits)
		fmt.Fprintf(&ir, "define i%d @fma_round%d(i%d %%a, i%d %%b, i%d %%c, i32 %%mode, i32 %%mxcsr) {\n", bits, bits, bits, bits, bits)
		for _, operand := range []string{"a", "b", "c"} {
			fmt.Fprintf(&ir, "  %%%s_float = bitcast i%d %%%s to %s\n", operand, bits, operand, floatType)
		}
		fmt.Fprintf(&ir, "  %%value = call %s @__plan9asm_fma3_round_f%d(%s %%a_float, %s %%b_float, %s %%c_float, i32 %%mode, i32 %%mxcsr)\n", floatType, bits, floatType, floatType, floatType)
		fmt.Fprintf(&ir, "  %%bits = bitcast %s %%value to i%d\n  ret i%d %%bits\n}\n", floatType, bits, bits)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fma3-fixed-round-extremes", triple, ir.String(), x86FMA3RoundingExtremeOracle, nil)
}

const x86FMA3RoundingExtremeOracle = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#pragma STDC FENV_ACCESS ON

extern uint32_t fma_round32(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
extern uint64_t fma_round64(uint64_t,uint64_t,uint64_t,uint32_t,uint32_t);

static uint64_t state=UINT64_C(0x71b32dd678098deb);
static uint64_t random_bits(void) {
    state^=state<<13; state^=state>>7; state^=state<<17;
    return state;
}

static uint64_t flush_input(uint64_t bits, uint64_t exponent, uint64_t sign, unsigned csr) {
    return (csr&64) && !(bits&exponent) ? bits&sign : bits;
}

static int check(unsigned width, uint64_t a, uint64_t b, uint64_t c,
                 unsigned mode, unsigned ambient, unsigned csr) {
    const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint64_t sign=width==32 ? UINT64_C(0x80000000) : UINT64_C(0x8000000000000000);
    uint64_t exponent=width==32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
    uint64_t got, expected=0;
    if (fesetround(modes[ambient])) return 1;
    if (feclearexcept(FE_ALL_EXCEPT)) return 5;
    if (width==32) got=fma_round32((uint32_t)a,(uint32_t)b,(uint32_t)c,mode,csr);
    else got=fma_round64(a,b,c,mode,csr);
    if (fegetround()!=modes[ambient]) return 2;
    if (fetestexcept(FE_ALL_EXCEPT)) return 6;
    a=flush_input(a,exponent,sign,csr);
    b=flush_input(b,exponent,sign,csr);
    c=flush_input(c,exponent,sign,csr);
    if (fesetround(modes[mode])) return 3;
    if (width==32) {
        uint32_t aa=(uint32_t)a, bb=(uint32_t)b, cc=(uint32_t)c, result_bits;
        float first, second, addend;
        memcpy(&first,&aa,4); memcpy(&second,&bb,4); memcpy(&addend,&cc,4);
        float result=fmaf(first,second,addend);
        memcpy(&result_bits,&result,4); expected=result_bits;
    } else {
        double first, second, addend;
        memcpy(&first,&a,8); memcpy(&second,&b,8); memcpy(&addend,&c,8);
        double result=fma(first,second,addend);
        memcpy(&expected,&result,8);
    }
    if ((csr&32768) && !(expected&exponent)) expected&=sign;
    if (got!=expected) {
        fprintf(stderr,"FMA rounding width/mode/ambient/csr %u/%u/%u/%x inputs=%llx,%llx,%llx got=%llx expected=%llx\n",
                width,mode,ambient,csr,(unsigned long long)a,(unsigned long long)b,
                (unsigned long long)c,(unsigned long long)got,(unsigned long long)expected);
        return 4;
    }
    return 0;
}

int main(void) {
    const uint64_t edges32[]={0,0x80000000,1,0x80000001,0x7fffff,0x800000,
        0x800001,0x7f7fffff,0xff7fffff,0x3f000000,0xbf000000,0x3f800000,
        0xbf800000,0x3f800001,0xbf800002};
    const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),1,
        UINT64_C(0x8000000000000001),UINT64_C(0xfffffffffffff),
        UINT64_C(0x10000000000000),UINT64_C(0x10000000000001),
        UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),
        UINT64_C(0x3fe0000000000000),UINT64_C(0xbfe0000000000000),
        UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),
        UINT64_C(0x3ff0000000000001),UINT64_C(0xbff0000000000002)};
    const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0};
    for (unsigned width=32; width<=64; width+=32) {
        const uint64_t *edges=width==32 ? edges32 : edges64;
        const uint64_t exponent=width==32 ? UINT64_C(0x7f800000) : UINT64_C(0x7ff0000000000000);
        const uint64_t exponent_low=width==32 ? UINT64_C(0x800000) : UINT64_C(0x10000000000000);
        for (unsigned i=0; i<5000; i++) {
            uint64_t a, b, c;
            if (i<3375) {
                a=edges[i%15]; b=edges[(i/15)%15]; c=edges[(i/225)%15];
            } else {
                a=random_bits(); b=random_bits(); c=random_bits();
                if (width==32) { a=(uint32_t)a; b=(uint32_t)b; c=(uint32_t)c; }
                if ((a&exponent)==exponent) a^=exponent_low;
                if ((b&exponent)==exponent) b^=exponent_low;
                if ((c&exponent)==exponent) c^=exponent_low;
            }
            for (unsigned mode=0; mode<4; mode++) {
                for (unsigned ambient=0; ambient<4; ambient++) {
                    for (unsigned control=0; control<4; control++) {
                        if (check(width,a,b,c,mode,ambient,controls[control])) return 1;
                    }
                }
            }
        }
    }
    return fesetround(FE_TONEAREST) ? 1 : 0;
}
`
