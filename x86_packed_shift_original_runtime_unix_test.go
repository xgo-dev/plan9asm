//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86PackedShiftOriginal396ActualHost(t *testing.T, member string) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("original complete packed-shift execution requires LLVM22 llc/clang")
	}
	kernels := x86PackedShiftOriginalRuntimeDirectory(t, member)
	want := 48
	if strings.HasSuffix(member, "W") {
		want = 36
	}
	if len(kernels) != want {
		t.Fatal("original complete member partition changed", member, len(kernels), want)
	}
	var source, declarations, externs, cases strings.Builder
	for _, kernel := range kernels {
		source.WriteString(kernel.source)
		fmt.Fprintf(&cases, "{%s,%q,%d,%d,%d,%d,%d,%d,0},\n", kernel.name, kernel.name,
			kernel.width, kernel.lane, kernel.operation, kernel.mode, kernel.zero, kernel.oldCounts)
	}
	declarations.WriteString(x86PackedShiftOriginalDeclarations(kernels, false))
	externs.WriteString(x86PackedShiftOriginalDeclarations(kernels, true))
	// The original 396 kernels are unmodified. Add twelve independent Full
	// immediate W witnesses per W member to execute the formerly incorrect
	// E4.nb class, without multiplying the entire physical grammar again.
	if strings.HasSuffix(member, "W") {
		uniform := strings.Replace(member, "VW", "W", 1)
		extra := 0
		for _, row := range x86PackedShiftRawCases() {
			if row.member.op != uniform || !row.evex || !row.immediate || row.input != "memory" || row.mask == 0 {
				continue
			}
			for _, raw := range []bool{false, true} {
				name := fmt.Sprint("fullImmediate", extra)
				extra++
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ data+0(FP),AX\nMOVQ counts+8(FP),BX\n"+
					"MOVQ out+16(FP),DI\nVMOVUPS (AX),Z0\nVMOVUPS (AX),Z2\nKMOVQ mask+24(FP),K1\n", name)
				if raw {
					source.WriteString(x86RawDisplacementDirectives(row.code(false)))
				} else {
					source.WriteString(row.instruction() + "\n")
				}
				source.WriteString("VMOVUPS Z2,(DI)\nVMOVUPS Y2,64(DI)\nVMOVUPS X2,96(DI)\nRET\n")
				fmt.Fprintf(&declarations, "func %s(data,counts,out *byte,mask uint64)\n", name)
				fmt.Fprintf(&externs, "extern void %s(const void*,const void*,void*,uint64_t);\n", name)
				operation, zero := 0, 0
				if uniform == "VPSRLW" {
					operation = 1
				} else if uniform == "VPSRAW" {
					operation = 2
				}
				if row.mask == 2 {
					zero = 1
				}
				fmt.Fprintf(&cases, "{%s,%q,%d,2,%d,3,%d,0,1},\n", name, name, row.width, operation, zero)
			}
		}
		if extra != 12 {
			t.Fatal("complete W Full-immediate regression partition changed", extra)
		}
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "Go")
	if err != nil || ir == "" {
		t.Fatal("actual original complete initialized kernels lost their execution consumer", err)
	}
	ir, err = x86PackedShiftPortableIR(source.String(), ir)
	if err != nil {
		t.Fatal("actual-host portable packed-shift projection lost exact source/IR ownership", err)
	}
	driver := x86PackedShiftOriginalActualHostHeader + x86PackedShiftOriginalC(t, externs.String()) +
		numericalRuntimeFaultObservationC + x86PackedShiftOriginalActualHostObservation +
		"static const struct shift_case cases[]={\n" + cases.String() + "};\n" + x86PackedShiftOriginalActualHostMain
	if err := runtimeOracleFaultCorePolicy(x86PackedShiftOriginalActualHostObservation); err != nil {
		t.Fatal("actual fault child lost the shared first-action resource policy", err)
	}
	for _, pipeline := range []struct {
		name     string
		backend  int
		optimize bool
	}{{"backend_O0", 0, false}, {"backend_O2", 2, false}, {"IR_O2_backend_O2", 2, true}} {
		t.Run(pipeline.name, func(t *testing.T) {
			input := ir
			if pipeline.optimize {
				input = x86DwordProductIROptimize(t, input)
			}
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "original-packed-shift", triple,
				input, driver, nil, pipeline.backend)
		})
	}
	t.Logf("%s: %d/396 original named/raw kernels, exact original C/96 samples/112-byte aliases/guard observations; <=48 functions; three pipelines; checked actual-host portable LLVM execution on every host, not original Go native qualification", member, len(kernels))
}

const x86PackedShiftOriginalActualHostHeader = `
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
`

const x86PackedShiftOriginalActualHostObservation = `
struct shift_case {
    void (*run)(const void*,const void*,void*,uint64_t);
    const char *name;
    unsigned width,bytes,operation,mode,zero,oldCounts,fullImmediate;
};
static int observe_original_shift(const struct shift_case *test,unsigned readable,uint64_t mask) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        uint8_t data[64],output[114],want[112]={0};
        memset(data,255,sizeof(data));
        memset(output,0xa7,sizeof(output));
        unsigned lanes=test->width/test->bytes;
        for(unsigned i=0;i<lanes;i++) {
            unsigned active=test->mode<2 || ((mask>>i)&1);
            unsigned byte=active?(test->fullImmediate?0:255):(!test->zero && !test->oldCounts?255:0);
            memset(want+i*test->bytes,byte,test->bytes);
        }
        memcpy(want+64,want,32);
        memcpy(want+96,want,16);
        numerical_fault_begin(guard+page,page);
        test->run(data,guard+page-readable,output+1,mask);
        if(output[0]!=0xa7 || output[113]!=0xa7 || memcmp(output+1,want,112)) _exit(122);
        for(unsigned i=0;i<64;i++) if(data[i]!=255) _exit(122);
        _exit(0);
    }
    int status=0;
    pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    if(waited!=child) return -2;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(numerical_fault_status(status)) return 1;
    return -3;
}
static int check_full_immediate(const struct shift_case *test) {
    for(unsigned sample=0;sample<96;sample++) {
        uint8_t data[64],memory[64],output[112],want[112]={0};
        for(unsigned i=0;i<64;i++) {
            data[i]=(uint8_t)(31*i+17*sample);
            memory[i]=(uint8_t)(71*i+23*sample+128);
        }
        unsigned lanes=test->width/test->bytes;
        uint64_t mask=sample==0?0:sample==1?UINT64_C(1)<<63:sample==2?UINT64_MAX:
            UINT64_C(0x5a5a01239876cdef)>>(sample%32);
        for(unsigned i=0;i<lanes;i++) {
            uint64_t value=(mask>>i)&1?shifted(lane(memory+i*test->bytes,test->bytes),5,16,test->operation):
                test->zero?0:lane(data+i*test->bytes,test->bytes);
            memcpy(want+i*test->bytes,&value,test->bytes);
        }
        memcpy(want+64,want,32);
        memcpy(want+96,want,16);
        test->run(data,memory,output,mask);
        if(memcmp(output,want,112)) return 1;
    }
    return 0;
}
static int check_shift_probe(const struct shift_case *test,unsigned readable,uint64_t mask,unsigned required) {
    int got=observe_original_shift(test,readable,mask);
    if(got!=(required>readable)) {
        fprintf(stderr,"%s readable=%u mask=%llx required=%u observation=%d\n",test->name,
                readable,(unsigned long long)mask,required,got);
        return 1;
    }
    return 0;
}
`

const x86PackedShiftOriginalActualHostMain = `
int main(void) {
    puts("PACKED_SHIFT_ACTUAL_HOST_PORTABLE_LLVM_NOT_ORIGINAL_GO_NATIVE");
    fflush(stdout);
    if(setup_guard()) return 2;
    memset(guard+page-64,0,64);
    unsigned original=0,immediate=0,probes=0;
    for(unsigned n=0;n<sizeof(cases)/sizeof(cases[0]);n++) {
        const struct shift_case *test=cases+n;
        if(test->fullImmediate) {
            if(check_full_immediate(test)) return 3;
            immediate++;
        } else {
            if(check(test->run,test->width,test->bytes,test->operation,test->mode,test->zero,test->oldCounts)) return 4;
            original++;
        }
        unsigned lanes=test->width/test->bytes;
        uint64_t last=UINT64_C(1)<<(lanes-1);
        if(test->mode==0 || test->mode==2) {
            /* The actual original VMOVUPS count producer reads all 64 bytes,
               even with a zero mask or a narrower shift destination. */
            if(check_shift_probe(test,63,0,64) || check_shift_probe(test,64,0,64)) return 5;
            probes+=2;
        } else if(test->mode==1) {
            if(check_shift_probe(test,test->width-1,0,test->width) ||
               check_shift_probe(test,test->width,0,test->width)) return 6;
            probes+=2;
        } else {
            unsigned lastRequired=test->mode==4?test->bytes:test->width;
            if(check_shift_probe(test,0,0,0) || check_shift_probe(test,0,UINT64_C(1)<<63,0) ||
               check_shift_probe(test,test->bytes-1,1,test->bytes) ||
               check_shift_probe(test,test->bytes,1,test->bytes) ||
               check_shift_probe(test,lastRequired-1,last,lastRequired) ||
               check_shift_probe(test,lastRequired,last,lastRequired)) return 7;
            probes+=6;
        }
    }
    if(free_guard()) return 8;
    printf("PACKED_SHIFT_ORIGINAL_C_VALUES_ALIASES_AND_STRICT_FAULTS_OK original=%u FullImmediate=%u probes=%u\n",
           original,immediate,probes);
    return 0;
}
`

func TestX86PackedShiftOriginal396CompanionIsPortableAndFaultStrict(t *testing.T) {
	complete := x86PackedShiftOriginalActualHostHeader + x86PackedShiftOriginalActualHostObservation + x86PackedShiftOriginalActualHostMain
	for _, native := range []string{"cpuid", "xgetbv", "__asm__", "__x86_64__", "__i386__"} {
		if strings.Contains(complete, native) {
			t.Fatal("portable companion gained host ISA qualification instead of checked portable IR", native)
		}
	}
	if strings.Count(complete, "PACKED_SHIFT_ACTUAL_HOST_PORTABLE_LLVM_NOT_ORIGINAL_GO_NATIVE") != 1 ||
		strings.Count(complete, "numerical_fault_begin(guard+page,page)") != 1 ||
		!strings.Contains(complete, "waited<0 && errno==EINTR") || !strings.Contains(complete, "waited!=child") ||
		!strings.Contains(complete, "numerical_fault_status(status)") {
		t.Fatal("portable companion lost its execution qualification or exact guarded-page observation")
	}
	if err := runtimeOracleFaultCorePolicy(x86PackedShiftOriginalActualHostObservation); err != nil {
		t.Fatal(err)
	}
}

func TestX86PackedShiftOriginal396ActualHostVPSLLVW(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSLLVW")
}

func TestX86PackedShiftOriginal396ActualHostVPSLLVD(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSLLVD")
}

func TestX86PackedShiftOriginal396ActualHostVPSLLVQ(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSLLVQ")
}

func TestX86PackedShiftOriginal396ActualHostVPSRLVW(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRLVW")
}

func TestX86PackedShiftOriginal396ActualHostVPSRLVD(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRLVD")
}

func TestX86PackedShiftOriginal396ActualHostVPSRLVQ(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRLVQ")
}

func TestX86PackedShiftOriginal396ActualHostVPSRAVW(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRAVW")
}

func TestX86PackedShiftOriginal396ActualHostVPSRAVD(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRAVD")
}

func TestX86PackedShiftOriginal396ActualHostVPSRAVQ(t *testing.T) {
	x86PackedShiftOriginal396ActualHost(t, "VPSRAVQ")
}
