//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This integer/page-protection oracle runs on the actual host. Foreign hosts
// exercise guarded volatile lowering, not native x86 qualification. Matching
// x86 hosts must actually have AVX2 and enabled XMM/YMM state, or fail.
func TestX86ExplicitMaskMoveActualHostValuesAliasesAndFaults(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("explicit mask move execution requires LLVM22 llc/clang")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, externs, cases strings.Builder
	for _, row := range x86ExplicitMaskMoveIndependentCases() {
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ p+0(FP),AX\nMOVQ data+8(FP),BX\n"+
			"MOVQ mask+16(FP),CX\nMOVQ out+24(FP),DX\nVMOVDQU (BX),%s0\n"+
			"VMOVDQU (CX),%s1\nSTC\n%s\n", row.name, row.bank, row.bank, row.instruction)
		if row.memory == 0 {
			// X loads must also clear the independently observable Y alias.
			source.WriteString("VMOVDQU Y2,(DX)\n")
		}
		source.WriteString("SETCS 32(DX)\nRET\n")
		fmt.Fprintf(&declarations, "func %s(p,data,mask,out *byte)\n", row.name)
		fmt.Fprintf(&externs, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint8_t*);\n", row.name)
		lane, store := 4, 0
		if strings.HasPrefix(row.instruction, "VMASKMOVPD ") || strings.HasPrefix(row.instruction, "VPMASKMOVQ ") {
			lane = 8
		}
		if row.memory == 2 {
			store = 1
		}
		fmt.Fprintf(&cases, "{%s,%d,%d,%d},\n", row.name, row.width, lane, store)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "Go")
	if err != nil {
		t.Fatal("actual initialized complete mask move execution source rejected", err)
	}
	driver := x86ExplicitMaskMoveActualHostHeader + numericalRuntimeFaultObservationC +
		x86ExplicitMaskMoveActualHostDriver + externs.String() +
		"static const struct testcase cases[]={\n" + cases.String() + "};\n" + x86ExplicitMaskMoveActualHostMain
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
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "explicit-mask-move", triple,
				input, driver, nil, pipeline.backend)
		})
	}
	t.Log("16 shapes; every lane-mask value, data canaries, Y aliases/CF and5 masks x3 guard extents x3 pipelines; original Go/native reference execution remains separate")
}

const x86ExplicitMaskMoveActualHostHeader = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
struct testcase {
    void (*run)(uint8_t*,const uint8_t*,const uint8_t*,uint8_t*);
    unsigned width,lane,store;
};
`

const x86ExplicitMaskMoveActualHostDriver = `
static void setmask(uint8_t *mask,unsigned width,unsigned lane,unsigned bits) {
    for(unsigned i=0;i<32;i++) mask[i]=(uint8_t)(0x35+17*i);
    for(unsigned i=0;i<width/lane;i++)
        mask[(i+1)*lane-1]=(uint8_t)((mask[(i+1)*lane-1]&127)|(((bits>>i)&1)<<7));
}
static int observe(const struct testcase *test,uint8_t *p,const uint8_t *data,const uint8_t *mask,
                   uint8_t *protectedPage,size_t protectedBytes) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        uint8_t out[33]={0};
        numerical_fault_begin(protectedPage,protectedBytes);
        test->run(p,data,mask,out);
        _exit(out[32]==1?0:121);
    }
    int status=0;
    pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0 && errno==EINTR);
    if(waited!=child) return -2;
    if(WIFEXITED(status) && WEXITSTATUS(status)==0) return 0;
    if(numerical_fault_status(status)) return 1;
    return -3;
}
static int host_preflight(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned a,b,c,d,avx=0,avx2=0,osxsave=0;
    uint64_t xcr0=0;
    if(__get_cpuid(1,&a,&b,&c,&d)) {
        avx=(c>>28)&1; osxsave=(c>>27)&1;
        if(osxsave) {
            unsigned low,high;
            __asm__ volatile("xgetbv" : "=a"(low),"=d"(high) : "c"(0));
            xcr0=((uint64_t)high<<32)|low;
        }
    }
    if(__get_cpuid_count(7,0,&a,&b,&c,&d)) avx2=(b>>5)&1;
    printf("EXPLICIT_MASK_MOVE AVX=%u AVX2=%u OSXSAVE=%u XCR0=%llx\n",
           avx,avx2,osxsave,(unsigned long long)xcr0);
    fflush(stdout);
    if(!avx || !avx2 || !osxsave || (xcr0&6)!=6) return 1;
#endif
    return 0;
}
`

const x86ExplicitMaskMoveActualHostMain = `
int main(void) {
    if(host_preflight()) return 1;
    uint8_t input[34],data[32],mask[32],out[34],memory[34];
    for(unsigned i=0;i<32;i++) {
        input[i+1]=(uint8_t)(0x21+7*i);
        data[i]=(uint8_t)(0xc3-3*i);
    }
    for(unsigned n=0;n<sizeof(cases)/sizeof(cases[0]);n++) {
        const struct testcase *test=cases+n;
        unsigned lanes=test->width/test->lane;
        for(unsigned pattern=0;pattern<(1u<<lanes);pattern++) {
            setmask(mask,test->width,test->lane,pattern);
            memset(out,0x69,sizeof(out));
            memset(memory,0x5a,sizeof(memory));
            test->run(test->store?memory+1:input+1,data,mask,out);
            if(out[32]!=1 || out[33]!=0x69) return 2;
            for(unsigned i=0;i<32;i++) {
                unsigned active=i<test->width && ((pattern>>(i/test->lane))&1);
                unsigned want=test->store?0x69:(active?input[i+1]:0);
                if(out[i]!=want) return 3;
                want=test->store && active?data[i]:0x5a;
                if(memory[i+1]!=want) return 4;
            }
            if(memory[0]!=0x5a || memory[33]!=0x5a) return 5;
        }
    }
    long page=sysconf(_SC_PAGESIZE);
    if(page<128) return 6;
    uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(region==MAP_FAILED || mprotect(region+page,page,PROT_NONE)) return 7;
    for(unsigned n=0;n<sizeof(cases)/sizeof(cases[0]);n++) {
        const struct testcase *test=cases+n;
        unsigned lanes=test->width/test->lane;
        unsigned masks[]={0,1,1u<<(lanes-1),0x55,(1u<<lanes)-1};
        unsigned extents[]={0,test->lane,test->width};
        for(unsigned m=0;m<5;m++) for(unsigned e=0;e<3;e++) {
            unsigned required=0;
            setmask(mask,test->width,test->lane,masks[m]);
            for(unsigned i=0;i<lanes;i++) if((masks[m]>>i)&1) required=(i+1)*test->lane;
            int got=observe(test,region+page-extents[e],data,mask,region+page,(size_t)page);
            if(got!=(required>extents[e])) {
                fprintf(stderr,"case=%u mask=%x extent=%u got=%d required=%u\n",n,masks[m],extents[e],got,required);
                return 8;
            }
        }
    }
    if(munmap(region,2*page)) return 9;
    puts("EXPLICIT_MASK_MOVE_VALUES_ALIASES_CF_AND_ACTIVE_LANE_FAULTS_OK");
    return 0;
}
`
