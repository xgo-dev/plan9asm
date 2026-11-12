//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ExtensionNativeResultsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	count := 0
	for _, row := range x86ExtensionNativeOracle {
		for _, dead := range []bool{false, true} {
			name, original := fmt.Sprintf("F%d", count), fmt.Sprintf("Original%d", count)
			body := row.op + " -1(DX)(BX*1),CX"
			native := "MOVQ $0x87654321fedcba98,AX\n" + row.op + " (DI),AX\n"
			if dead {
				body += "\nMOVQ $0x87654321fedcba98,CX"
				native += "MOVQ $0x87654321fedcba98,AX\n"
			}
			asm, decl := x86ExtensionNativeFixture(name, "amd64", body, false)
			source.WriteString(asm)
			declarations.WriteString(decl)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\n"+native+"RET\n")
			var bytes []string
			for _, b := range code {
				bytes = append(bytes, fmt.Sprintf("0x%02x", b))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
			fmt.Fprintf(&prototypes, "extern uint64_t %s(const uint8_t*);\nextern uint64_t %s(const uint8_t*);\n", name, original)
			signed, discarded := 0, 0
			if row.signed {
				signed = 1
			}
			if dead {
				discarded = 1
			}
			fmt.Fprintf(&rows, "{%s,%s,%d,%d,%d,%d},\n", name, original, row.source, row.destination, signed, discarded)
			count++
		}
	}
	if count != 28 {
		t.Fatal("incomplete live/dead extension family", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	driver := fmt.Sprintf(x86ExtensionNativeRuntimeC, prototypes.String(), originals.String(), rows.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					text, level := ir, "-O0"
					if optimized {
						text, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "extension-native", text, driver, level)
					if string(output) != "28 extension kernels: numerical 3584, fault 336, tripwires 2; failures 0\n" {
						t.Fatal("original/LLVM extension semantics or read envelope differs:", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

const x86ExtensionNativeRuntimeC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
%s
%s
typedef uint64_t (*Program)(const uint8_t*);
typedef struct {
    Program translated, original;
    unsigned width, destination, sign, dead;
} Kernel;
static const Kernel kernels[]={%s};
static const uint64_t seed=UINT64_C(0x87654321fedcba98);

static uint64_t reference(Kernel k, const uint8_t *p) {
    if(k.dead) return seed;
    uint64_t value=0;
    for(unsigned b=0;b<k.width;b++) value|=(uint64_t)p[b]<<(8*b);
    if(k.sign && (p[k.width-1]&0x80)) value|=UINT64_MAX<<(8*k.width);
    if(k.destination==2) return (seed&~UINT64_C(0xffff))|(value&0xffff);
    if(k.destination==4) return value&UINT64_C(0xffffffff);
    return value;
}

static int fault(Program run, const uint8_t *p) {
    pid_t child=fork();
    if(child<0) return -1;
    if(child==0) {
        struct rlimit no_core={0,0};
        if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        volatile uint64_t result=run(p);
        (void)result;
        _exit(0);
    }
    int status=0;
    if(waitpid(child,&status,0)!=child) return -2;
    if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
    if(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -4;
}

static uint64_t missing_read(const uint8_t *p) { (void)p; return seed; }
static uint64_t too_wide(const uint8_t *p) { return *(volatile const uint64_t*)p; }

int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if(page<128) return 1;
    uint8_t *memory=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(memory==MAP_FAILED || mprotect(memory+page,page,PROT_NONE)) return 2;
    memset(memory,0xa7,page);
    if(fault(missing_read,NULL)!=0 || fault(too_wide,memory+page-4)!=1) return 3;
    unsigned numerical=0, faults=0;
    for(unsigned i=0;i<sizeof(kernels)/sizeof(kernels[0]);i++) {
        Kernel k=kernels[i];
        for(unsigned pattern=0;pattern<64;pattern++) {
            uint8_t bytes[8];
            for(unsigned b=0;b<sizeof(bytes);b++) bytes[b]=(uint8_t)(pattern*37+b*11);
            // Both aligned and unaligned inputs; sign and high preserved bytes vary.
            const uint8_t *p=bytes+(pattern&1);
            uint64_t want=reference(k,p);
            if(k.original(p)!=want || k.translated(p)!=want) {
                fprintf(stderr,"kernel %%u pattern %%u expected %%llx\n",i,pattern,(unsigned long long)want);
                return 4;
            }
            numerical+=2;
        }
        for(unsigned address=0;address<6;address++) {
            // NULL, zero/short/full/extra extents, and ordinary unaligned storage.
            unsigned available[]={0,0,k.width-1,k.width,k.width+1,0};
            const uint8_t *p=address==0?NULL:address==5?memory+1:memory+page-available[address];
            int want=address<3;
            if(fault(k.original,p)!=want || fault(k.translated,p)!=want) {
                fprintf(stderr,"kernel %%u address %%u expected fault %%d\n",i,address,want);
                return 5;
            }
            faults+=2;
        }
    }
    if(munmap(memory,2*page)) return 6;
    printf("28 extension kernels: numerical %%u, fault %%u, tripwires 2; failures 0\n",numerical,faults);
    return 0;
}
`
