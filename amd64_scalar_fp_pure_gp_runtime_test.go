package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PureGPUnknownDeadOutputs(t *testing.T) {
	x86PureGPUnknownRuntime(t, false)
}

func x86PureGPUnknownRuntime(t *testing.T, bmi2 bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	var source, declaration, prototypes, originals, pairs strings.Builder
	var cases []x86PureGPUnknownCase
	for _, row := range x86PureGPUnknownCases("amd64") {
		isBMI2 := strings.HasPrefix(row.body, "SARX") || strings.HasPrefix(row.body, "SHLX") ||
			strings.HasPrefix(row.body, "SHRX") || strings.HasPrefix(row.body, "RORX")
		if isBMI2 == bmi2 {
			cases = append(cases, row)
		}
	}
	for index, row := range cases {
		name, original := fmt.Sprintf("view%d", index), fmt.Sprintf("original%d", index)
		// seed is deliberately not imported into LLVM scratch registers. The
		// original Go byte oracle supplies several possible physical values;
		// neither program's observable result may depend on those values.
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-20\nMOVL $1,AX\nCMPL AX,AX\n%s\nMOVSS x+0(FP),X0\nMOVSS X0,ret+16(FP)\nRET\n", name, row.body)
		fmt.Fprintf(&declaration, "func %s(x,seed uint64) uint32\n", name)
		actual := x86PackedShiftActualGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\nPUSHQ BX\nMOVQ SI,BX\nMOVQ SI,CX\nMOVQ SI,DX\nMOVL $1,AX\nCMPL AX,AX\n"+row.body+"\nMOVL DI,AX\nPOPQ BX\nRET\n")
		if len(actual) < 20 || actual[len(actual)-1] != 0xc3 {
			t.Fatal("incomplete original Go byte program", row.body, actual)
		}
		var bytes []string
		for _, b := range actual {
			bytes = append(bytes, fmt.Sprintf("0x%02x", b))
		}
		symbol := original
		if strings.Contains(execution.triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
		fmt.Fprintf(&prototypes, "extern uint32_t %s(uint64_t,uint64_t);\n", name)
		prototypes.WriteString(x86OriginalSysVDeclaration("uint32_t", original, "uint64_t,uint64_t"))
		fmt.Fprintf(&pairs, "{%s,%s},\n", name, original)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	requireBMI2 := 0
	if bmi2 {
		requireBMI2 = 1
	}
	main := fmt.Sprintf("#define REQUIRE_BMI2 %d\n", requireBMI2) + `
#include <stdint.h>
#include <stdio.h>
#include <xmmintrin.h>
` + prototypes.String() + originals.String() + x86OriginalSysVPointer("uint32_t", "original_program", "uint64_t,uint64_t") + `
typedef uint32_t (*program)(uint64_t,uint64_t);
struct pair { program translated; original_program original; };
static const struct pair pairs[]={
` + pairs.String() + `};
int main(void) {
    __builtin_cpu_init();
    if(REQUIRE_BMI2 && !__builtin_cpu_supports("bmi2")) {
        fprintf(stderr,"original Go BMI2 oracle requires BMI2 execution\n");
        return 2;
    }
    const uint64_t seeds[]={0,1,15,31,32,63,64,255,UINT64_MAX,
        UINT64_C(0x0123456789abcdef),UINT64_C(0x8000000000000000)};
    for(unsigned i=0;i<sizeof(pairs)/sizeof(*pairs);++i) {
        for(unsigned s=0;s<sizeof(seeds)/sizeof(*seeds);++s) {
            for(unsigned n=0;n<17;++n) {
                uint64_t x=UINT64_C(0x9e3779b97f4a7c15)*n;
                uint32_t saved=_mm_getcsr(),csr=0x1f80|((n%4)<<13);
                _mm_setcsr(csr);
                uint32_t a=pairs[i].original(x,seeds[s]);
                uint32_t b=pairs[i].translated(x,seeds[s]);
                uint32_t after=_mm_getcsr();
                _mm_setcsr(saved);
                if(a!=(uint32_t)x || b!=a || after!=csr) {
                    fprintf(stderr,"kernel=%u seed=%u pattern=%u original=%x llvm=%x want=%x\n",
                        i,s,n,a,b,(uint32_t)x);
                    return 1;
                }
            }
        }
    }
    printf("%zu pure GP programs x 11 seeds x 17 observable patterns\n",sizeof(pairs)/sizeof(*pairs));
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir},
				{"IR_O2/backend_O2", "-O2", x86MulDivRoundOptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					out := execution.compileAndRunLLVM(t, "pure-gp-unknown", pipeline.ir, main, pipeline.level)
					want := fmt.Sprintf("%d pure GP programs x 11 seeds x 17 observable patterns\n", len(cases))
					if string(out) != want {
						t.Fatalf("unexpected original/LLVM receipt: %q", out)
					}
					t.Log(strings.TrimSpace(string(out)))
				})
			}
		})
	}
	t.Logf("original Go opcode/LLVM numerical observations; transport=%s/%s, not a foreign native-ABI certificate", runtime.GOOS, runtime.GOARCH)
}
