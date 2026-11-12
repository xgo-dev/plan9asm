//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// These are integer bit patterns, never host floating casts. Include both
// zeros, signed subnormals, normal fractions, qNaN/sNaN, infinities and both
// sides of signed/unsigned 32/64-bit result boundaries.
var x86ScalarFloatIntegerSSInputs = []uint64{
	0, 0x80000000, 1, 0x80000001, 0x3f000000, 0xbf000000, 0x3fc00000, 0xbfc00000,
	0x7fc12345, 0x7f812345, 0xffc12345, 0xff812345, 0x7f800000, 0xff800000,
	0x4effffff, 0x4f000000, 0xceffffff, 0xcf000000, 0xcf000001,
	0x4f7fffff, 0x4f800000, 0x5effffff, 0x5f000000, 0xdf000000, 0xdf000001,
	0x5f7fffff, 0x5f800000, 0x7f7fffff,
}

var x86ScalarFloatIntegerSDInputs = []uint64{
	0, 0x8000000000000000, 1, 0x8000000000000001, 0x3fe0000000000000, 0xbfe0000000000000, 0x3ff8000000000000, 0xbff8000000000000,
	0x7ff8123456789abc, 0x7ff0123456789abc, 0xfff8123456789abc, 0xfff0123456789abc, 0x7ff0000000000000, 0xfff0000000000000,
	0x41dfffffffc00000, 0x41e0000000000000, 0xc1dfffffffc00000, 0xc1e0000000000000, 0xc1e0000000200000,
	0x41efffffffe00000, 0x41f0000000000000, 0x43dfffffffffffff, 0x43e0000000000000, 0xc3e0000000000000, 0xc3e0000000000001,
	0x43efffffffffffff, 0x43f0000000000000, 0x7fefffffffffffff,
}

func x86ScalarFloatIntegerNumericalFixture(vector bool) (assembly, declarations, original, driver string, count int) {
	var asm, decl, gcalls, cdecl, ccalls strings.Builder
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		if strings.HasPrefix(name, "V") != vector {
			continue
		}
		suffixes := []string{""}
		if vector {
			if strings.Contains(name, "CVTT") {
				suffixes = append(suffixes, ".SAE")
			} else {
				suffixes = append(suffixes, ".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE")
			}
		}
		for _, suffix := range suffixes {
			fn := fmt.Sprintf("matrix%d", count)
			precision := 0
			if strings.Contains(name, "SD") {
				precision = 1
			}
			fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$8-20\nSTMXCSR saved-4(SP)\nMOVQ out+0(FP),DI\nMOVQ bits+8(FP),AX\nMOVQ AX,X0\nLDMXCSR csr+16(FP)\nMOVQ $-1,CX\nCMPQ CX,$-1\n%s%s X0,AX\nMOVQ AX,0(DI)\nSTMXCSR 8(DI)\nSETEQ 16(DI)\nSETCS 17(DI)\nSETOS 18(DI)\nSETMI 19(DI)\nSETPC 20(DI)\nLDMXCSR saved-4(SP)\nRET\n", fn, name, suffix)
			fmt.Fprintf(&decl, "func %s(out *[4]uint64,bits uint64,csr uint32)\n", fn)
			sae := 0
			if suffix != "" {
				sae = 1
			}
			fmt.Fprintf(&gcalls, "check(%d,%d,%d,%s)\n", count, precision, sae, fn)
			fmt.Fprintf(&cdecl, "extern void %s(uint64_t*,uint64_t,uint32_t);\n", fn)
			fmt.Fprintf(&ccalls, "check(%d,%d,%d,%s);\n", count, precision, sae, fn)
			count++
		}
	}
	var gvalues, cvalues strings.Builder
	for _, values := range [][]uint64{x86ScalarFloatIntegerSSInputs, x86ScalarFloatIntegerSDInputs} {
		gvalues.WriteString("{")
		cvalues.WriteString("{")
		for _, value := range values {
			fmt.Fprintf(&gvalues, "%#x,", value)
			fmt.Fprintf(&cvalues, "UINT64_C(%#x),", value)
		}
		gvalues.WriteString("},")
		cvalues.WriteString("},")
	}
	original = `package main
import "fmt"
var inputs = [][]uint64{` + gvalues.String() + `}
func check(index,precision,sae int,fn func(*[4]uint64,uint64,uint32)) {
    for n,bits:=range inputs[precision] {
        for rc:=0;rc<4;rc++ { for controls:=0;controls<4;controls++ {
            csr:=uint32(0x1f80|rc<<13|0x21)
            if controls&1!=0 {csr|=0x40}; if controls&2!=0 {csr|=0x8000}
            if sae!=0 {csr &^= 0x1080} // SAE must also suppress unmasked IE/PE.
            out:=[4]uint64{0x1111111111111111,0x2222222222222222,0x3333333333333333,0x4444444444444444}
            fn(&out,bits,csr)
            fmt.Printf("%d %d %d %d %016x %016x %016x %016x\n",index,n,rc,controls,out[0],out[1],out[2],out[3])
        }}
    }
}
` + decl.String() + "func main(){\n" + gcalls.String() + "}\n"
	driver = `#include <stdint.h>
#include <stdio.h>
static const uint64_t inputs[2][28]={` + cvalues.String() + `};
static void check(unsigned index,unsigned precision,unsigned sae,void (*fn)(uint64_t*,uint64_t,uint32_t)) {
    for(unsigned n=0;n<28;n++) for(unsigned rc=0;rc<4;rc++) for(unsigned controls=0;controls<4;controls++) {
        uint32_t csr=0x1f80|(rc<<13)|0x21;
        if(controls&1) csr|=0x40; if(controls&2) csr|=0x8000;
        if(sae) csr&=~UINT32_C(0x1080);
        uint64_t out[]={UINT64_C(0x1111111111111111),UINT64_C(0x2222222222222222),UINT64_C(0x3333333333333333),UINT64_C(0x4444444444444444)};
        fn(out,inputs[precision][n],csr);
        printf("%u %u %u %u %016llx %016llx %016llx %016llx\n",index,n,rc,controls,(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2],(unsigned long long)out[3]);
    }
}
` + cdecl.String() + "int main(void){\n" + ccalls.String() + "return 0;}\n"
	return asm.String(), decl.String(), original, driver, count
}

func x86ScalarFloatIntegerNumericalMatrix(t *testing.T, vector bool) {
	t.Helper()
	axis := x86FloatCompareSSE
	if vector {
		axis = x86FloatCompareEVEX
	}
	execution := x86FloatCompareRuntimeTools(t, axis)
	assembly, declarations, original, driver, count := x86ScalarFloatIntegerNumericalFixture(vector)
	want := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original)
	if rows := strings.Count(string(want), "\n"); rows != count*28*16 {
		t.Fatalf("incomplete original Go receipt: %d expected %d", rows, count*28*16)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, input)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%v/backend%s", optimized, level), func(t *testing.T) {
						got := execution.compileAndRunLLVM(t, "scalar-conversion-matrix", input, driver, level)
						if string(got) != string(want) {
							actual, expected := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
							for i := 0; i < len(actual) && i < len(expected); i++ {
								if actual[i] != expected[i] {
									t.Fatalf("row %d: LLVM %s; original Go %s", i, actual[i], expected[i])
								}
							}
							t.Fatal("output length differs from complete original Go receipt")
						}
					})
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerLegacyIEEEAndFlags(t *testing.T) {
	x86ScalarFloatIntegerNumericalMatrix(t, false)
}
