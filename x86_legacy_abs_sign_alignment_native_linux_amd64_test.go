package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These required roots execute actual native opcode bytes. Rosetta/QEMU and
// an object-only or portable mathematical result cannot qualify legacy #GP.
func TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaultsAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	execution.compiler = append(execution.compiler, "-mssse3")
	x86LegacyAbsSignNativeAlignment(t, execution, "amd64")
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaults386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required native ABS/sign mode32 tools: LLVM22=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie", "-mssse3"}}
	x86LegacyAbsSignNativeAlignment(t, execution, "386")
	x87IA32RequireNativeHost(t)
}

func x86LegacyAbsSignNativeAlignment(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	if len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("original legacy alignment exceptions require native direct execution")
	}
	// A missing instruction-set prerequisite must fail before SIGILL could be
	// mistaken for an access exception. AVX is a required unaligned control.
	directory := t.TempDir()
	preflight, probe := filepath.Join(directory, "isa.c"), filepath.Join(directory, "isa")
	if err := os.WriteFile(preflight, []byte(`#include <stdio.h>
int main(void) {
    __builtin_cpu_init();
    int ssse3=!!__builtin_cpu_supports("ssse3"),avx=!!__builtin_cpu_supports("avx");
    printf("ABS/sign actual native SSSE3=%d AVX=%d\n",ssse3,avx);
    return ssse3&&avx?0:1;
}
`), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, preflight, probe)
	t.Logf("%s", strings.TrimSpace(string(execution.run(t, probe))))
	source, declarations := x86AbsSignAlignmentProgram(arch, true)
	x86LEAActualTargetGoObject(t, arch, execution.triple, source)
	code := x86AbsSignAlignmentOriginalBytes(t, arch)
	references, kernels := x86AbsSignAlignmentNativeReferences(t, code)
	driver := x86MemoryFaultSupportC + references + x86LegacyAbsSignAlignmentNativeC +
		"static const struct abs_sign_case cases[]={\n" + kernels + "};\n" + x86LegacyAbsSignAlignmentNativeMainC
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, "Go")
	if err != nil || ir == "" {
		t.Fatal("original initialized native live/dead program rejected", err)
	}
	for _, pipeline := range []struct{ name, body, level string }{
		{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
		{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			executable := execution.compileLLVM(t, "abs-sign-original-alignment", pipeline.body, driver, pipeline.level)
			var ia32 x87IA32Executable
			if arch == "386" {
				ia32 = x86NativeOracleIA32Executable(t, execution, executable)
			}
			observe := func(row, probe, original int) string {
				if arch == "386" {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				outcome := x86ObserveMemoryFault(t, execution, executable, row, probe, original)
				if arch == "386" {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				return outcome
			}
			for index, row := range x86AbsSignAlignmentRows() {
				for role, name := range []string{"live", "dead"} {
					t.Run(row.opcode+"/"+name, func(t *testing.T) {
						for probe := 0; probe < 20; probe++ {
							returns := probe == 2 || probe == 3 || !row.legacy && probe >= 4 && probe <= 18
							want := observe(2*index+role, probe, 1)
							if returns && want != "return" || !returns && want != "segv" && want != "bus" {
								t.Fatal("original Go opcode violated independent alignment/access matrix", probe, want)
							}
							if got := observe(2*index+role, probe, 0); got != want {
								t.Fatal("translated native alignment/dead fault differs from original Go bytes", probe, got, want)
							}
						}
						t.Log("ABS/sign original Go bytes and LLVM native alignment/access/CF/MXCSR=0x1f80/canary probes 20 failures 0")
					})
				}
			}
		})
	}
}

const x86LegacyAbsSignAlignmentNativeC = `
typedef void (*abs_sign_call)(uint8_t*,const uint8_t*,const uint8_t*);
struct abs_sign_case {
    abs_sign_call translated,original;
    unsigned lane,sign,legacy,live;
};
static uint32_t abs_sign_read(const uint8_t *p,unsigned lane) {
    uint32_t value=0;
    for (unsigned i=0;i<lane;i++) value|=(uint32_t)p[i]<<(8*i);
    return value;
}
static void abs_sign_expected(uint8_t *out,const uint8_t *input,const uint8_t *old,
        struct abs_sign_case k) {
    uint32_t sign=UINT32_C(1)<<(k.lane*8-1);
    uint32_t all=k.lane==4?UINT32_MAX:(UINT32_C(1)<<(k.lane*8))-1;
    for (unsigned at=0;at<16;at+=k.lane) {
        uint32_t data=abs_sign_read(k.sign?old+at:input+at,k.lane),value;
        if (k.sign) {
            uint32_t control=abs_sign_read(input+at,k.lane);
            value=!control?0:(control&sign)?(UINT32_C(0)-data)&all:data;
        } else value=(data&sign)?(UINT32_C(0)-data)&all:data;
        for (unsigned byte=0;byte<k.lane;byte++) out[at+byte]=(uint8_t)(value>>(8*byte));
    }
}
`

const x86LegacyAbsSignAlignmentNativeMainC = `
int main(int argc,char **argv) {
    unsigned row,probe,original;
    char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&row,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 || sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            row>=sizeof(cases)/sizeof(cases[0]) || probe>=20 || original>1) return 80;
    int setup=memory_fault_setup(0);
    if (setup) return setup;
    if ((uintptr_t)guard%16 || page%16) return 81;
    struct abs_sign_case k=cases[row];
    const uint8_t *input=probe==0?NULL:probe==1?guard+page-15:
        probe==2||probe==3?guard+page-16:probe==19?guard+page:guard+probe-3;
    int returns=probe==2||probe==3||(!k.legacy&&probe>=4&&probe<=18);
    if (probe>=4 && probe<=18 && (uintptr_t)input%16!=probe-3) return 82;
    if (probe==3 && mprotect(guard,page,PROT_READ)) return 83;
    uint8_t old[48],before_old[48],out[48],expected[48];
    for (unsigned i=0;i<48;i++) old[i]=(uint8_t)(i*31+0x80);
    memcpy(before_old,old,sizeof(old));
    memset(out,0xc3,sizeof(out));memset(expected,0xc3,sizeof(expected));
    if (returns && k.live) abs_sign_expected(expected+1,input,old+1,k);
    expected[17]=1;
    /* AMD MisAlignSSE permits an optional MXCSR.MM bit17. Fix the exact
       Intel/AMD common MM=0 mode, rather than assuming an inherited value
       or guessing exception behavior from a vendor name or CPUID alone. */
    uint32_t fixed_mxcsr=UINT32_C(0x1f80),observed_mxcsr=0;
    __asm__ volatile("ldmxcsr %0" : : "m"(fixed_mxcsr) : "memory");
    __asm__ volatile("stmxcsr %0" : "=m"(observed_mxcsr) : : "memory");
    if (observed_mxcsr!=fixed_mxcsr) return 90;
    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 84;
    (original?k.original:k.translated)(out+1,input,old+1);
    /* Never read an inaccessible source after an unexpected normal return:
       that would manufacture a C fault and falsely qualify the opcode. */
    if (!returns) return 85;
    __asm__ volatile("stmxcsr %0" : "=m"(observed_mxcsr) : : "memory");
    if (observed_mxcsr!=fixed_mxcsr) return 91;
    if (memcmp(out,expected,sizeof(out)) || memcmp(old,before_old,sizeof(old))) return 86;
    for (size_t i=0;i<page;i++) if (guard[i]!=(uint8_t)(i*13+17)) return 87;
    if (free_guard()) return 88;
    puts("memory complete");
    return fflush(stdout)?89:0;
}
`
