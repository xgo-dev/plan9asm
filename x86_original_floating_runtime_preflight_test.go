package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func x86OriginalFloatingRuntimeAllowsSkip(mode string, profile int, output []byte, err error) bool {
	// Require a plain process exit. Joined timeout, pipe or cleanup errors are
	// failures even if one of their causes happens to be exit78.
	status, ok := err.(*exec.ExitError)
	if mode != "auto" || !ok || status.ExitCode() != 78 || profile < 1 || profile > 4 {
		return false
	}
	const format = "original-floating profile=%d SSE2=%d AVX=%d OSXSAVE=%d AVX512F=%d AVX512VL=%d FMA=%d SSSE3=%d AVX2=%d XCR0=%x"
	var actual int
	var sse2, avx, osxsave, f, vl, fma, ssse3, avx2 uint
	var xcr0 uint64
	receipt := strings.TrimSpace(string(output))
	n, scanErr := fmt.Sscanf(receipt, format, &actual, &sse2, &avx, &osxsave, &f, &vl, &fma, &ssse3, &avx2, &xcr0)
	if scanErr != nil || n != 10 || actual != profile ||
		receipt != fmt.Sprintf(format, actual, sse2, avx, osxsave, f, vl, fma, ssse3, avx2, xcr0) {
		return false
	}
	for _, bit := range []uint{sse2, avx, osxsave, f, vl, fma, ssse3, avx2} {
		if bit > 1 {
			return false
		}
	}
	capable := sse2 == 1 && avx == 1 && osxsave == 1 && f == 1 && xcr0&0xe6 == 0xe6
	if profile == 2 {
		capable = capable && vl == 1 && fma == 1
	}
	if profile == 4 {
		capable = capable && vl == 1 && ssse3 == 1 && avx2 == 1
	}
	return !capable
}

// Diagnose this original owner's actual execution route. These observations
// cannot authorize another runner or replace the original numerical verdict.
func x86OriginalFloatingRuntimeRequireCPU(t *testing.T, profile, clang, triple string, prefix []string) {
	t.Helper()
	mode := os.Getenv("PLAN9ASM_AVX512_RUNTIME")
	if mode != "" && mode != "required" && mode != "auto" {
		t.Fatalf("invalid PLAN9ASM_AVX512_RUNTIME %q: expected required or auto", mode)
	}
	var required int
	switch profile {
	case "scalar-precision":
		required = 1
	case "fma-caller":
		required = 2
	case "unsigned-scalar-integer":
		required = 3
	case "packed-abs-sign":
		required = 4
	case "estimate14-F":
		required = 5
	case "estimate14-FVL":
		required = 6
	default:
		t.Fatal("unknown original floating execution profile", profile)
	}
	execution := x86FloatCompareExecution{
		compiler: []string{clang, "-target", triple},
		triple:   triple,
		prefix:   prefix,
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "original-floating-preflight.c")
	executable := filepath.Join(directory, gotoolchain.HostExecutable("original-floating-preflight"))
	program := fmt.Sprintf("#define REQUIRED_PROFILE %d\n", required) +
		x86OriginalFloatingRuntimeStateC + x86OriginalFloatingRuntimeOpcodeC
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	command := execution.command(executable)
	ctx, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, command[0], command[1:]...))
	cancel()
	t.Logf("actual original floating allocation profile=%s triple=%s prefix=%q: %s", profile, triple, prefix, output)
	if x86OriginalFloatingRuntimeAllowsSkip(mode, required, output, err) {
		t.Skipf("AVX512 native execution unavailable (PLAN9ASM_AVX512_RUNTIME=auto); object checks remain required, runtime not verified: %s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		t.Fatalf("original floating CPU/opcode preflight failed: %v\n%s", err, output)
	}
}

// Scalar EVEX conversions require F, not packed narrow VL, DQ or BW. The
// complete FMA owner additionally executes VEX FMA and narrow packed EVEX.
// ABS/sign needs F/VL plus its independently observed legacy SSSE3/AVX2.
// Keep this predicate portable so independent negative rows never execute ISA.
const x86OriginalFloatingRuntimeStateC = `#include <stdint.h>
static int original_floating_required_state(unsigned profile,unsigned sse2,unsigned avx,
                                            unsigned osxsave,unsigned f,unsigned vl,
                                            unsigned fma,uint64_t xcr0) {
    if (!sse2 || !avx || !osxsave || !f || (xcr0&0xe6)!=0xe6) return 0;
    return profile==1 || profile==3 || profile==5 || (profile==2 && vl && fma) || ((profile==4 || profile==6) && vl);
}
static int original_packed_abs_sign_required_legacy(unsigned ssse3,unsigned avx2) {
    return ssse3 && avx2;
}
`

// Only these independent probe functions have native target attributes. The
// baseline entry prints real CPUID/XCR0 before any unsupported opcode can run.
const x86OriginalFloatingRuntimeOpcodeC = `
#include <stdio.h>
#include <cpuid.h>
#if !defined(_WIN32)
#include <sys/resource.h>
#endif

__attribute__((target("avx512f")))
static int original_scalar_precision(void) {
    uint32_t narrow=1;
    uint64_t wide=1;
    unsigned mask=1;
    __asm__ volatile("vxorps %%xmm0,%%xmm0,%%xmm0; kmovw %2,%%k1; "
                     "vcvtsd2ss %{rn-sae%},%%xmm0,%%xmm0,%%xmm1%{%%k1%}; vmovss %%xmm1,%0; "
                     "vcvtss2sd %{sae%},%%xmm0,%%xmm0,%%xmm1%{%%k1%}%{z%}; vmovsd %%xmm1,%1"
                     : "=m"(narrow),"=m"(wide) : "r"(mask) : "xmm0","xmm1","k1","memory");
    return narrow==0 && wide==0;
}

__attribute__((target("avx,fma,avx512f,avx512vl")))
static int original_fma_caller(void) {
    uint32_t scalar=1,packed[8];
    uint64_t wide[8];
    unsigned mask=0xffff;
    __asm__ volatile("vxorps %%xmm0,%%xmm0,%%xmm0; "
                     "vfmadd132ss %%xmm0,%%xmm0,%%xmm0; vmovss %%xmm0,%0; "
                     "vxorps %%ymm0,%%ymm0,%%ymm0; kmovw %3,%%k1; "
                     "vfmadd132ps %%ymm0,%%ymm0,%%ymm0%{%%k1%}; vmovups %%ymm0,%1; "
                     "vpxord %%zmm0,%%zmm0,%%zmm0; "
                     "vfmadd132pd %%zmm0,%%zmm0,%%zmm0; vmovupd %%zmm0,%2"
                     : "=m"(scalar),"=m"(packed),"=m"(wide) : "r"(mask) : "zmm0","k1","memory");
    if (scalar) return 0;
    for (unsigned i=0;i<8;i++) if (packed[i] || wide[i]) return 0;
    return 1;
}

__attribute__((target("avx512f")))
static int original_unsigned_scalar_integer(void) {
    uint32_t source32=0xffffffffu,narrow[2]={1,1};
    uint64_t source64=0xffffffffffffffffULL,wide[2]={1,1};
    __asm__ volatile("vxorps %%xmm0,%%xmm0,%%xmm0; "
                     "vcvtusi2sdl %4,%%xmm0,%%xmm1; vmovsd %%xmm1,%0; "
                     "vcvtusi2sdq %5,%{rz-sae%},%%xmm0,%%xmm1; vmovsd %%xmm1,%1; "
                     "vcvtusi2ssl %6,%{rd-sae%},%%xmm0,%%xmm1; vmovss %%xmm1,%2; "
                     "vcvtusi2ssq %5,%{rn-sae%},%%xmm0,%%xmm1; vmovss %%xmm1,%3"
                     : "=m"(wide[0]),"=m"(wide[1]),"=m"(narrow[0]),"=m"(narrow[1])
                     : "m"(source32),"r"(source64),"r"(source32) : "xmm0","xmm1","memory");
    return wide[0]==0x41efffffffe00000ULL && wide[1]==0x43efffffffffffffULL &&
           narrow[0]==0x4f7fffffu && narrow[1]==0x5f800000u;
}

__attribute__((target("ssse3,avx2,avx512f,avx512vl")))
static int original_packed_abs_sign(void) {
    uint32_t source[16] __attribute__((aligned(64)))={0};
    uint32_t legacy[4],vex[8],masked[8];
    uint64_t wide[8];
    unsigned mask=1;
    __asm__ volatile("vpxor %%ymm0,%%ymm0,%%ymm0; vpabsb %%xmm0,%%xmm0; "
                     "psignw %4,%%xmm0; vmovdqu %%xmm0,%0; "
                     "vpsignd %%ymm0,%%ymm0,%%ymm0; vmovdqu %%ymm0,%1; "
                     "kmovw %5,%%k1; vpxor %%ymm1,%%ymm1,%%ymm1; "
                     "vpabsd %4%{1to8%},%%ymm1%{%%k1%}; vmovdqu %%ymm1,%2; "
                     "vpxord %%zmm0,%%zmm0,%%zmm0; "
                     "vpabsq %%zmm0,%%zmm1%{%%k1%}%{z%}; vmovdqu64 %%zmm1,%3"
                     : "=m"(legacy),"=m"(vex),"=m"(masked),"=m"(wide)
                     : "m"(source),"r"(mask) : "zmm0","zmm1","k1","memory");
    for (unsigned i=0;i<4;i++) if (legacy[i]) return 0;
    for (unsigned i=0;i<8;i++) if (vex[i] || masked[i] || wide[i]) return 0;
    return 1;
}

__attribute__((target("avx512f")))
static int original_estimate14_f(void) {
    uint32_t single[16]; uint64_t wide[8],packed[4][8];
    for(unsigned i=0;i<16;i++) single[i]=0x3f800000u;
    for(unsigned i=0;i<8;i++) wide[i]=UINT64_C(0x3ff0000000000000);
    unsigned mask=1;
    uint32_t scalar32[2]; uint64_t scalar64[2];
    __asm__ volatile("vmovups %8,%%zmm0; vmovupd %9,%%zmm1; kmovw %10,%%k1; "
                     "vrcp14ps %%zmm0,%%zmm2%{%%k1%}%{z%}; vmovups %%zmm2,%0; "
                     "vrcp14pd %%zmm1,%%zmm2%{%%k1%}%{z%}; vmovups %%zmm2,%1; "
                     "vrsqrt14ps %%zmm0,%%zmm2%{%%k1%}%{z%}; vmovups %%zmm2,%2; "
                     "vrsqrt14pd %%zmm1,%%zmm2%{%%k1%}%{z%}; vmovups %%zmm2,%3; "
                     "vrcp14ss %%xmm0,%%xmm0,%%xmm2%{%%k1%}%{z%}; vmovss %%xmm2,%4; "
                     "vrcp14sd %%xmm1,%%xmm1,%%xmm2%{%%k1%}%{z%}; vmovsd %%xmm2,%5; "
                     "vrsqrt14ss %%xmm0,%%xmm0,%%xmm2%{%%k1%}%{z%}; vmovss %%xmm2,%6; "
                     "vrsqrt14sd %%xmm1,%%xmm1,%%xmm2%{%%k1%}%{z%}; vmovsd %%xmm2,%7; "
                     : "=m"(packed[0]),"=m"(packed[1]),"=m"(packed[2]),"=m"(packed[3]),"=m"(scalar32[0]),"=m"(scalar64[0]),"=m"(scalar32[1]),"=m"(scalar64[1])
                     : "m"(single),"m"(wide),"r"(mask) : "zmm0","zmm1","zmm2","k1","memory");
    for(unsigned i=0;i<4;i++) for(unsigned j=0;j<8;j++) {
        uint64_t expected=j?0:(i%2?UINT64_C(0x3ff0000000000000):UINT64_C(0x3f800000));
        if(packed[i][j]!=expected) return 0;
    }
    if(scalar32[0]!=0x3f800000u || scalar32[1]!=0x3f800000u || scalar64[0]!=UINT64_C(0x3ff0000000000000) || scalar64[1]!=UINT64_C(0x3ff0000000000000)) return 0;
    return 1;
}

__attribute__((target("avx512f,avx512vl")))
static int original_estimate14_fvl(void) {
    uint32_t single[16]; uint64_t wide[8],packed[8][8];
    for(unsigned i=0;i<16;i++) single[i]=0x3f800000u;
    for(unsigned i=0;i<8;i++) wide[i]=UINT64_C(0x3ff0000000000000);
    unsigned mask=1;
    __asm__ volatile("vmovups %8,%%zmm0; vmovupd %9,%%zmm1; kmovw %10,%%k1; "
                     "vrcp14ps %%xmm0,%%xmm2%{%%k1%}%{z%}; vmovups %%zmm2,%0; "
                     "vrcp14pd %%xmm1,%%xmm2%{%%k1%}%{z%}; vmovups %%zmm2,%1; "
                     "vrsqrt14ps %%xmm0,%%xmm2%{%%k1%}%{z%}; vmovups %%zmm2,%2; "
                     "vrsqrt14pd %%xmm1,%%xmm2%{%%k1%}%{z%}; vmovups %%zmm2,%3; "
                     "vrcp14ps %%ymm0,%%ymm2%{%%k1%}%{z%}; vmovups %%zmm2,%4; "
                     "vrcp14pd %%ymm1,%%ymm2%{%%k1%}%{z%}; vmovups %%zmm2,%5; "
                     "vrsqrt14ps %%ymm0,%%ymm2%{%%k1%}%{z%}; vmovups %%zmm2,%6; "
                     "vrsqrt14pd %%ymm1,%%ymm2%{%%k1%}%{z%}; vmovups %%zmm2,%7; "
                     : "=m"(packed[0]),"=m"(packed[1]),"=m"(packed[2]),"=m"(packed[3]),"=m"(packed[4]),"=m"(packed[5]),"=m"(packed[6]),"=m"(packed[7])
                     : "m"(single),"m"(wide),"r"(mask) : "zmm0","zmm1","zmm2","k1","memory");
    for(unsigned i=0;i<8;i++) for(unsigned j=0;j<8;j++) {
        uint64_t expected=j?0:(i%2?UINT64_C(0x3ff0000000000000):UINT64_C(0x3f800000));
        if(packed[i][j]!=expected) return 0;
    }
    return 1;
}

int main(void) {
#if !defined(_WIN32)
    struct rlimit no_core={0,0};
    if (setrlimit(RLIMIT_CORE,&no_core)) return 77;
#endif
    unsigned a,b,c,d,sse2=0,avx=0,osxsave=0,f=0,vl=0,fma=0,ssse3=0,avx2=0;
    uint64_t xcr0=0;
    if (__get_cpuid(1,&a,&b,&c,&d)) {
        sse2=(d>>26)&1; avx=(c>>28)&1; osxsave=(c>>27)&1; fma=(c>>12)&1;
        ssse3=(c>>9)&1;
        if (osxsave) {
            unsigned low,high;
            __asm__ volatile("xgetbv" : "=a"(low),"=d"(high) : "c"(0));
            xcr0=((uint64_t)high<<32)|low;
        }
    }
    if (__get_cpuid_count(7,0,&a,&b,&c,&d)) {
        f=(b>>16)&1; vl=(b>>31)&1;
        avx2=(b>>5)&1;
    }
    unsigned profile=REQUIRED_PROFILE;
    printf("original-floating profile=%u SSE2=%u AVX=%u OSXSAVE=%u AVX512F=%u AVX512VL=%u FMA=%u SSSE3=%u AVX2=%u XCR0=%llx\n",
           profile,sse2,avx,osxsave,f,vl,fma,ssse3,avx2,(unsigned long long)xcr0);
    fflush(stdout);
    if (!original_floating_required_state(profile,sse2,avx,osxsave,f,vl,fma,xcr0)) return 78;
    if (profile==4 && !original_packed_abs_sign_required_legacy(ssse3,avx2)) return 78;
    if (profile==1 && !original_scalar_precision()) return 79;
    if (profile==2 && !original_fma_caller()) return 80;
    if (profile==3 && !original_unsigned_scalar_integer()) return 81;
    if (profile==4 && !original_packed_abs_sign()) return 82;
    if (profile==5 && !original_estimate14_f()) return 83;
    if (profile==6 && !original_estimate14_fvl()) return 84;
    puts("ORIGINAL_FLOATING_RUNTIME_CPU_OPCODES_OK");
    return 0;
}
`
