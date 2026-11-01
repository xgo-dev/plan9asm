package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Required Linux owners execute the original low-bank Go bytes directly.
// A portable mathematical companion, emulator or machine object cannot
// qualify actual Type4 alignment faults and dead/zero-mask native reads.
func TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaultsAMD64(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	execution.compiler = append(execution.compiler, "-mavx2")
	x86BlendMinposNativeFaults(t, execution, "amd64")
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaults386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	llc := findLLVM22Tool("llc")
	compiler, err := exec.LookPath("i686-linux-gnu-gcc")
	if llc == "" || err != nil {
		t.Fatalf("required native mode32 tools: LLVM22=%q compiler=%v", llc, err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "i386-unknown-linux-gnu",
		compiler: []string{compiler, "-static", "-no-pie", "-mavx2"}}
	x86BlendMinposNativeFaults(t, execution, "386")
	x87IA32RequireNativeHost(t)
}

func x86BlendMinposNativeFaults(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	if len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("original blend/minimum faults require direct native execution")
	}
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "isa.c"), filepath.Join(directory, "isa")
	if err := os.WriteFile(source, []byte(`#include <stdio.h>
int main(void) {
    __builtin_cpu_init();
    int sse41=!!__builtin_cpu_supports("sse4.1"),avx2=!!__builtin_cpu_supports("avx2");
    printf("blend/minimum actual native SSE4.1=%d AVX2=%d\n",sse41,avx2);
    return sse41&&avx2?0:1;
}
`), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("%s", strings.TrimSpace(string(execution.run(t, executable))))
	assembly, declarations, codes := x86BlendMinposNativeProgram(t, arch)
	x86LEAActualTargetGoObject(t, arch, execution.triple, assembly)
	references, cases := x86BlendMinposNativeReferences(t, codes)
	driver := x86MemoryFaultSupportC + references + x86BlendMinposNativeModelC +
		"static const struct blend_minpos_case cases[]={\n" + cases + "};\n" + x86BlendMinposNativeMainC
	ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, arch, execution.triple, "Go")
	if err != nil || ir == "" {
		t.Fatal("complete initialized original blend/minimum program rejected", err)
	}
	for _, pipeline := range []struct{ name, body, level string }{
		{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
		{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			program := execution.compileLLVM(t, "blend-minimum-original-faults", pipeline.body, driver, pipeline.level)
			var ia32 x87IA32Executable
			if arch == "386" {
				ia32 = x86NativeOracleIA32Executable(t, execution, program)
			}
			observe := func(row, probe, original int) string {
				if arch == "386" {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				outcome := x86ObserveMemoryFault(t, execution, program, row, probe, original)
				if arch == "386" {
					if err := ia32.verify(); err != nil {
						t.Fatal(err)
					}
				}
				return outcome
			}
			for index, row := range x86BlendMinposMemoryRows() {
				for role, name := range []string{"live", "dead"} {
					for zero := 0; zero < 2; zero++ {
						t.Run(fmt.Sprintf("%s/%s/%s/maskzero=%d", row.op, row.bank, name, zero), func(t *testing.T) {
							for probe := 0; probe < 20; probe++ {
								returns := probe == 2 || probe == 3 || !row.legacy && probe >= 4 && probe <= 18
								want := observe(4*index+2*role+zero, probe, 1)
								if returns && want != "return" || !returns && want != "segv" && want != "bus" {
									t.Fatal("actual Go bytes differ from independent alignment/access oracle", probe, want)
								}
								if got := observe(4*index+2*role+zero, probe, 0); got != want {
									t.Fatal("translated actual opcode/read differs from original bytes", probe, got, want)
								}
							}
							t.Log("blend/minimum original Go bytes and LLVM native alignment/access/CF/MXCSR=0x1f80/canary probes 20 failures 0")
						})
					}
				}
			}
		})
	}
}

const x86BlendMinposNativeModelC = `
typedef void (*blend_minpos_call)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*);
struct blend_minpos_case {
    blend_minpos_call translated,original;
    unsigned width,lane,minimum,legacy,live,zero;
};
static void blend_minpos_expected(uint8_t *out,const uint8_t *input,
        const uint8_t *old,const uint8_t *mask,struct blend_minpos_case k) {
    if (!k.live) return;
    if (k.minimum) {
        unsigned minimum=65535,position=0;
        for (unsigned i=0;i<8;i++) {
            unsigned value=(unsigned)input[2*i]|((unsigned)input[2*i+1]<<8);
            if (value<minimum) {minimum=value;position=i;}
        }
        memset(out,0,16);out[0]=(uint8_t)minimum;out[1]=(uint8_t)(minimum>>8);out[2]=(uint8_t)position;
    } else for (unsigned at=0;at<k.width;at+=k.lane) {
        const uint8_t *chosen=(mask[at+k.lane-1]&128)?input:old;
        memcpy(out+at,chosen+at,k.lane);
    }
}
`

const x86BlendMinposNativeMainC = `
int main(int argc,char **argv) {
    unsigned row,probe,original;
    char tail;
    if (argc!=4 || sscanf(argv[1],"%u%c",&row,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 || sscanf(argv[3],"%u%c",&original,&tail)!=1 ||
            row>=sizeof(cases)/sizeof(cases[0]) || probe>=20 || original>1) return 80;
    int setup=memory_fault_setup(0);
    if (setup) return setup;
    struct blend_minpos_case k=cases[row];
    if ((uintptr_t)guard%32 || page%32) return 81;
    const uint8_t *input=probe==0?NULL:probe==1?guard+page-k.width+1:
        probe==2||probe==3?guard+page-k.width:probe==19?guard+page:guard+probe-3;
    int returns=probe==2||probe==3||(!k.legacy&&probe>=4&&probe<=18);
    if (probe>=4 && probe<=18 && (uintptr_t)input%16!=probe-3) return 82;
    if (probe==3 && mprotect(guard,page,PROT_READ)) return 83;
    uint8_t old[48],mask[48],before_old[48],before_mask[48],out[96],expected[96];
    for (unsigned i=0;i<48;i++) {
        old[i]=(uint8_t)(i*31+0x80);mask[i]=k.zero?0:(uint8_t)(i*73+0x80);
    }
    memcpy(before_old,old,sizeof(old));memcpy(before_mask,mask,sizeof(mask));
    memset(out,0xc3,sizeof(out));memset(expected,0xc3,sizeof(expected));
    if (returns) blend_minpos_expected(expected+1,input,old+1,mask+1,k);
    expected[65]=1;
    /* Fix AMD MisAlignSSE's optional MM bit to the common MM=0 mode. */
    uint32_t fixed_mxcsr=UINT32_C(0x1f80),observed_mxcsr=0;
    __asm__ volatile("ldmxcsr %0" : : "m"(fixed_mxcsr) : "memory");
    __asm__ volatile("stmxcsr %0" : "=m"(observed_mxcsr) : : "memory");
    if (observed_mxcsr!=fixed_mxcsr) return 90;
    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 84;
    (original?k.original:k.translated)(out+1,input,old+1,mask+1);
    /* Never create a C fault by reading input after unexpected return. */
    if (!returns) return 85;
    __asm__ volatile("stmxcsr %0" : "=m"(observed_mxcsr) : : "memory");
    if (observed_mxcsr!=fixed_mxcsr) return 91;
    if (memcmp(out,expected,sizeof(out)) || memcmp(old,before_old,sizeof(old)) ||
            memcmp(mask,before_mask,sizeof(mask))) return 86;
    for (size_t i=0;i<page;i++) if (guard[i]!=(uint8_t)(i*13+17)) return 87;
    if (free_guard()) return 88;
    puts("memory complete");
    return fflush(stdout)?89:0;
}
`
