package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type x86FloatCompareRuntimeISA uint8

const (
	x86FloatCompareSSE x86FloatCompareRuntimeISA = iota + 1
	x86FloatCompareVEX
	x86FloatCompareEVEX
)

// These are independent fixture axes, not production grammar or permission.
func (fixture x86FloatCompareOracleCase) executionISA() x86FloatCompareRuntimeISA {
	if fixture.legacy {
		return x86FloatCompareSSE
	}
	if fixture.maskResult {
		return x86FloatCompareEVEX
	}
	return x86FloatCompareVEX
}

func x86FloatCompareRuntimeCases(opcode string, axis x86FloatCompareRuntimeISA) []x86FloatCompareOracleCase {
	var selected []x86FloatCompareOracleCase
	for _, fixture := range x86FloatCompareOracleCases(opcode) {
		if fixture.executionISA() == axis {
			selected = append(selected, fixture)
		}
	}
	return selected
}

func x86FloatCompareRuntimeTools(t *testing.T, axis x86FloatCompareRuntimeISA) x86FloatCompareExecution {
	t.Helper()
	if axis < x86FloatCompareSSE || axis > x86FloatCompareEVEX {
		t.Fatal("unknown compare execution ISA", axis)
	}
	if axis != x86FloatCompareSSE && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Fatal("VEX/EVEX comparison must consume its required Linux execution counterpart")
	}
	if axis == x86FloatCompareEVEX && runtime.GOARCH != "amd64" {
		t.Fatal("EVEX requires actual native Linux AMD64, not an emulator or Rosetta")
	}
	execution := x86FloatCompareExecutionTools(t)
	if axis == x86FloatCompareEVEX && (len(execution.prefix) != 0 || execution.preserveArgv0) {
		t.Fatal("EVEX native counterpart cannot use a guest execution route")
	}
	x86FloatCompareVerifyArguments(t, execution)
	if axis == x86FloatCompareVEX {
		execution.requireAVX(t)
	}
	x86FloatCompareRequireOpcodeISA(t, execution, axis)
	return execution
}

// CPUID and enabled OS register state are both required. The original whole
// opcodes execute only after this check; their results are consumed. This is
// an execution preflight, not a production source/ISA authorization token.
const x86FloatCompareOpcodePreflightC = `#include <stdint.h>
#include <stdio.h>
#include <cpuid.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

static int required_state(unsigned axis, unsigned sse2, unsigned avx,
                          unsigned osxsave, unsigned f, unsigned vl, uint64_t xcr0) {
    if (axis==1) return sse2!=0;
    if (!sse2 || !avx || !osxsave || (xcr0&6)!=6) return 0;
    if (axis==2) return 1;
    return axis==3 && f && vl && (xcr0&0xe6)==0xe6;
}

__attribute__((target("avx"))) static unsigned original_vex(void) {
    unsigned mask;
    __asm__ volatile("vxorps %%xmm0,%%xmm0,%%xmm0; "
                     "vcmpps $0,%%xmm0,%%xmm0,%%xmm1; "
                     "vmovmskps %%xmm1,%0" : "=r"(mask) :: "xmm0","xmm1");
    return mask;
}

__attribute__((target("avx512f,avx512vl"))) static int original_evex(void) {
    unsigned ps,pd,ss,sd,active;
    __asm__ volatile("vxorps %%zmm0,%%zmm0,%%zmm0; "
                     "vcmpps $0,%%zmm0,%%zmm0,%%k1; kmovw %%k1,%0; "
                     "vcmppd $0,%%zmm0,%%zmm0,%%k1; kmovw %%k1,%1; "
                     "vcmpss $0,%%xmm0,%%xmm0,%%k1; kmovw %%k1,%2; "
                     "vcmpsd $0,%%xmm0,%%xmm0,%%k1; kmovw %%k1,%3; "
                     "movl $1,%4; kmovw %4,%%k2; "
                     "vcmpps $0,%%zmm0,%%zmm0,%%k1%{%%k2%}; kmovw %%k1,%4"
                     : "=r"(ps),"=r"(pd),"=r"(ss),"=r"(sd),"=r"(active)
                     :: "zmm0","k1","k2");
    return ps==0xffff && pd==0xff && ss==1 && sd==1 && active==1;
}

int main(void) {
#if !defined(_WIN32)
    struct rlimit no_core={0,0};
    if (setrlimit(RLIMIT_CORE,&no_core)) return 77;
#endif
    unsigned a,b,c,d,sse2=0,avx=0,osxsave=0,f=0,vl=0;
    uint64_t xcr0=0;
    if (__get_cpuid(1,&a,&b,&c,&d)) {
        sse2=(d>>26)&1; avx=(c>>28)&1; osxsave=(c>>27)&1;
        if (osxsave) {
            unsigned low,high;
            __asm__ volatile("xgetbv" : "=a"(low),"=d"(high) : "c"(0));
            xcr0=((uint64_t)high<<32)|low;
        }
    }
    if (__get_cpuid_count(7,0,&a,&b,&c,&d)) {
        f=(b>>16)&1; vl=(b>>31)&1;
    }
    unsigned axis=REQUIRED_AXIS;
    printf("axis=%u SSE2=%u AVX=%u OSXSAVE=%u AVX512F=%u AVX512VL=%u XCR0=%llx\n",
           axis,sse2,avx,osxsave,f,vl,(unsigned long long)xcr0);
    fflush(stdout);
    if (!required_state(axis,sse2,avx,osxsave,f,vl,xcr0)) return 78;
    if (axis==2 && original_vex()!=15) return 79;
    if (axis==3 && !original_evex()) return 80;
    return 0;
}
`

func x86FloatCompareRequireOpcodeISA(t *testing.T, execution x86FloatCompareExecution, axis x86FloatCompareRuntimeISA) {
	t.Helper()
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "preflight.c"), filepath.Join(dir, "preflight")
	program := fmt.Sprintf("#define REQUIRED_AXIS %d\n", axis) + x86FloatCompareOpcodePreflightC
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	output := execution.run(t, executable)
	t.Logf("actual CPU/OS-state and original-opcode preflight: %s", output)
}

func TestX86FloatingCompareRuntimeCaseUnion(t *testing.T) {
	counts, dead := [3]int{}, [3]int{}
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		complete := x86FloatCompareOracleCases(opcode)
		// Scalar variant 1/2 intentionally have identical memory spellings.
		// Preserve their original multiplicity instead of dropping a fixture.
		remaining := make(map[x86FloatCompareOracleCase]int)
		for _, fixture := range complete {
			remaining[fixture]++
		}
		for _, axis := range []x86FloatCompareRuntimeISA{x86FloatCompareSSE, x86FloatCompareVEX, x86FloatCompareEVEX} {
			for _, fixture := range x86FloatCompareRuntimeCases(opcode, axis) {
				if remaining[fixture] == 0 {
					t.Fatal("duplicated runtime case", fixture.row)
				}
				remaining[fixture]--
				counts[axis-1]++
				if x86FloatCompareDeadPredicate(fixture.predicate) {
					dead[axis-1]++
				}
			}
		}
		for fixture, count := range remaining {
			if count != 0 {
				t.Fatal("missing runtime case", opcode, fixture.row, count)
			}
		}
	}
	if counts != [3]int{64, 256, 512} || dead != [3]int{16, 48, 96} {
		t.Fatalf("changed complete fixture denominators: IEEE=%v dead=%v", counts, dead)
	}
	var fp [3]int
	for _, fixture := range x86FloatCompareFPOracles(t) {
		fp[fixture.axis-1]++
	}
	if fp != [3]int{16, 16, 16} {
		t.Fatal("changed FP byte-field runtime denominator", fp)
	}
}

func TestX86FloatingCompareCompleteRuntimeOriginalGoInventory(t *testing.T) {
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		t.Run(opcode, func(t *testing.T) {
			assembly, _ := x86FloatCompareOracleAssembly(x86FloatCompareOracleCases(opcode), false)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		})
	}
	var dead []x86FloatCompareOracleCase
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		for _, fixture := range x86FloatCompareOracleCases(opcode) {
			if x86FloatCompareDeadPredicate(fixture.predicate) {
				dead = append(dead, fixture)
			}
		}
	}
	assembly, _ := x86FloatCompareOracleAssembly(dead, true)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	assembly, _ = x86FloatCompareFPAssembly(x86FloatCompareFPOracles(t))
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	t.Log("actual stock Go objects bind 832 independent IEEE, 160 dead-result and all 48 scalar FP-byte-field programs; object evidence does not imply ISA execution")
}

func TestX86FloatingCompareOpcodePreflightCapabilities(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "capabilities.c"), filepath.Join(dir, "capabilities")
	// Execute the exact preflight predicate against independent missing-feature
	// cases, without substituting synthetic capabilities for an actual ISA run.
	const checks = `
#undef main
int main(void) {
    if (!required_state(1,1,0,0,0,0,0) || required_state(1,0,1,1,1,1,0xe6)) return 1;
    if (!required_state(2,1,1,1,0,0,6) || !required_state(3,1,1,1,1,1,0xe6)) return 2;
    if (required_state(0,1,1,1,1,1,0xe6) || required_state(4,1,1,1,1,1,0xe6)) return 3;
    for (unsigned axis=2;axis<=3;axis++) {
        if (required_state(axis,0,1,1,1,1,0xe6) || required_state(axis,1,0,1,1,1,0xe6) ||
            required_state(axis,1,1,0,1,1,0xe6)) return 4;
        if (required_state(axis,1,1,1,1,1,0xe6&~2) ||
            required_state(axis,1,1,1,1,1,0xe6&~4)) return 5;
    }
    if (required_state(3,1,1,1,0,1,0xe6) || required_state(3,1,1,1,1,0,0xe6)) return 6;
    for (unsigned bit=5;bit<=7;bit++) {
        if (required_state(3,1,1,1,1,1,0xe6&~(1u<<bit))) return 7;
    }
    return 0;
}
`
	program := "#define REQUIRED_AXIS 1\n#define main actual_preflight_main\n" + x86FloatCompareOpcodePreflightC + checks
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	execution.run(t, executable)
}
