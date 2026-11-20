//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86ByteShuffleMemoryFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, entries strings.Builder
	count := 0
	for _, width := range []int{16, 32, 64} {
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
		for legacy := 0; legacy < 2; legacy++ {
			if legacy != 0 && width != 16 {
				continue
			}
			for masking := 0; masking < 3; masking++ {
				if legacy != 0 && masking != 0 {
					continue
				}
				for dead := 0; dead < 2; dead++ {
					name := fmt.Sprint("Fault", count)
					count++
					row := "VPSHUFB"
					if legacy != 0 {
						row = "PSHUFB"
					}
					if masking == 2 {
						row += ".Z"
					}
					row += " (SI)," + bank + "1"
					if masking != 0 {
						row += ",K1"
					}
					if legacy == 0 {
						row += "," + bank + "1"
					}
					fmt.Fprintf(&declarations, "func %s(out,control,data *[64]byte)\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ control+8(FP),SI\nMOVQ data+16(FP),DX\nVMOVUPS (DX),Z1\nMOVL $0,AX\nKMOVQ AX,K1\n%s\n", name, row)
					if dead == 0 {
						fmt.Fprintf(&source, "VMOVUPS %s1,(DI)\n", bank)
					}
					source.WriteString("RET\n")
					fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*);\n", name)
					original := "0"
					if legacy != 0 {
						// Original Go bytes use the native C argument registers.
						// This does not claim native VEX/EVEX execution.
						original = "Original" + name
						native := "TEXT native(SB),4,$0-0\nMOVOU (DX),X1\nPSHUFB (SI),X1\n"
						if dead == 0 {
							native += "MOVOU X1,(DI)\n"
						}
						code := x86OrderingHintGoBytes(t, "amd64", native+"RET\n")
						var bytes []string
						for _, value := range code {
							bytes = append(bytes, fmt.Sprintf("0x%02x", value))
						}
						symbol := original
						if strings.Contains(execution.triple, "apple") {
							symbol = "_" + symbol
						}
						fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
						fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*);\n", original)
					}
					fmt.Fprintf(&entries, "{%s,%s,%d,%d,%d},\n", name, original, width, masking, dead)
				}
			}
		}
	}
	if count != 20 {
		t.Fatal("incomplete fault family", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	driver := fmt.Sprintf(x86ByteShuffleFaultReference, prototypes.String(), originals.String(), entries.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					text := ir
					if level == "-O2" {
						text = x86MulDivRoundOptimize(t, text)
					}
					output := execution.compileAndRunLLVM(t, "byte-shuffle-faults", text, driver, level)
					if string(output) != "byte shuffle: 20 kernels, 110 address outcomes, failures 0\n" {
						t.Fatal("incomplete fault oracle", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

const x86ByteShuffleFaultReference = `
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
typedef void (*Program)(uint8_t*,const uint8_t*,const uint8_t*);
typedef struct { Program translated, original; int width, masking, dead; } Kernel;
static const Kernel kernels[] = {%s};

static int observe(Program run, Kernel k, const uint8_t *control) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        struct rlimit no_core = {0,0};
        if (setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
        _Alignas(64) uint8_t data[64], out[66];
        for (int i=0;i<64;i++) data[i]=(uint8_t)(i*17+31);
        memset(out,0xa7,sizeof(out));
        run(out+1,control,data);
        for (int i=0;i<66;i++) {
            unsigned want=0xa7;
            if (!k.dead && i>=1 && i<=k.width) {
                int offset=i-1;
                if (k.masking) want=k.masking==2 ? 0 : data[offset];
                else want=control[offset]&0x80 ? 0 : data[offset/16*16+(control[offset]&15)];
            }
            if (out[i]!=want) _exit(121);
        }
        _exit(0);
    }
    int status;
    if (waitpid(child,&status,0)!=child) return -2;
    if (WIFEXITED(status)) return WEXITSTATUS(status)==0 ? 0 : -3;
    if (WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) return 1;
    return -4;
}

int main(void) {
    long page=sysconf(_SC_PAGESIZE);
    if (page<128) return 1;
    uint8_t *memory=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if (memory==MAP_FAILED || mprotect(memory+page,page,PROT_NONE)) return 2;
    for (long i=0;i<page;i++) memory[i]=(uint8_t)(i*53+7);
    unsigned outcomes=0;
    for (unsigned i=0;i<sizeof(kernels)/sizeof(kernels[0]);i++) {
        Kernel k=kernels[i];
        const uint8_t *addresses[]={NULL,memory+page-k.width+1,memory+page-k.width,memory+1,memory};
        for (unsigned j=0;j<sizeof(addresses)/sizeof(addresses[0]);j++) {
            int got=observe(k.translated,k,addresses[j]);
            int want=j<2;
            if (k.original) {
                want=observe(k.original,k,addresses[j]);
                // Native hardware and Rosetta can differ on unaligned SSE.
                // Compare actual original behavior, never label it native CI.
                if (want<0 || (j<2 && want!=1) || (j>1 && j!=3 && want!=0)) return 3;
                outcomes++;
            }
            if (got<0 || got!=want) {
                fprintf(stderr,"kernel %%u address %%u got %%d want %%d\n",i,j,got,want);
                return 4;
            }
            outcomes++;
        }
    }
    if (munmap(memory,2*page)) return 5;
    printf("byte shuffle: %%zu kernels, %%u address outcomes, failures 0\n",sizeof(kernels)/sizeof(kernels[0]),outcomes);
    return 0;
}
`
