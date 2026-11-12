//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86CMOVUnconditionalFaultEnvelopes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, prototypes, originals, rows strings.Builder
	declarations.WriteString("package faultoracle\n")
	count := 0
	for _, width := range []string{"W", "L", "Q"} {
		for condition, row := range x86CMOVOracleConditions {
			for _, dead := range []bool{false, true} {
				fn := fmt.Sprintf("F%d", count)
				count++
				name := "CMOV" + width + row.name
				store, nativeStore := "MOVQ out+16(FP),DX\nMOVQ BX,(DX)\n", "MOVQ AX,(DX)\n"
				if dead {
					store, nativeStore = "", ""
				}
				fmt.Fprintf(&declarations, "func %s(p *[8]byte,seed uint64,out *uint64)\n", fn)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-24\nMOVQ p+0(FP),DI\nMOVQ seed+8(FP),AX\nMOVQ $0x87654321fedcba98,BX\nPUSHQ AX\nPOPFQ\n%s (DI),BX\n%sRET\n", fn, name, store)
				original := "Original" + fn
				actual := x86OrderingHintGoBytes(t, "amd64", "TEXT native(SB),4,$0-0\nMOVQ $0x87654321fedcba98,AX\nPUSHQ SI\nPOPFQ\n"+name+" (DI),AX\n"+nativeStore+"RET\n")
				var bytes []string
				for _, value := range actual {
					bytes = append(bytes, fmt.Sprintf("0x%02x", value))
				}
				symbol := original
				if strings.Contains(execution.triple, "apple") {
					symbol = "_" + symbol
				}
				fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint64_t,uint64_t*);\nextern void %s(const uint8_t*,uint64_t,uint64_t*);\n", fn, original)
				fmt.Fprintf(&rows, "{%s,%s,%d,%d},\n", fn, original, map[string]int{"W": 2, "L": 4, "Q": 8}[width], condition)
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	reference := fmt.Sprintf(x86CMOVFaultC, prototypes.String(), originals.String(), rows.String())
	for _, pipeline := range []struct{ name, backend, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "cmov-fault", pipeline.ir, reference, pipeline.backend)
			want := fmt.Sprintf("cmov live/dead kernels %d translated/original fault outcomes %d false/live/dead tripwires 4 failures 0\n", count, count*2*7*2)
			if string(output) != want {
				t.Fatal("unconditional exact-width source fault disagreement", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

const x86CMOVFaultC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
` + x86CMOVConditionC + `
%s
%s
typedef void(*Program)(const uint8_t*,uint64_t,uint64_t*);
typedef struct {Program translated,original;unsigned width,condition;} Kernel;
static Kernel kernels[]={%s};
static int observe(Program p,unsigned width,unsigned address,uint64_t flags) {
 pid_t child=fork();if(child<0) return -1;
 if(child==0) {
  struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
  uint8_t data[16];memset(data,0xa7,sizeof(data));const uint8_t *input=data;
  if(address==1) input++;
  if(address==2) input=NULL;
  if(address>=3) {
   long page=sysconf(_SC_PAGESIZE);if(page<=0) _exit(121);
   uint8_t *memory=mmap(NULL,2*(size_t)page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
   if(memory==MAP_FAILED) _exit(122);
   memset(memory,0xa7,(size_t)page);
   if(mprotect(memory+page,(size_t)page,PROT_NONE)) _exit(123);
   unsigned available[]={0,width-1,width,width+1};input=memory+page-available[address-3];
  }
  uint64_t out=0;p(input,flags,&out);_exit(0);
 }
 int status=0;if(waitpid(child,&status,0)!=child) return -2;
 if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
 if(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS)) return 1;
 return -4;
}
static void missing_read(const uint8_t*p,uint64_t f,uint64_t*out) {(void)p;(void)f;(void)out;}
static void too_wide(const uint8_t*p,uint64_t f,uint64_t*out) {(void)f;*out=*(volatile const uint64_t*)p;}
int main(void) {
 unsigned count=0;
 // Negative observers prove faults are real, not a forged list of outcomes.
 if(observe(missing_read,8,2,0)!=0||observe(missing_read,8,4,0)!=0||observe(too_wide,2,5,0)!=1||observe(too_wide,4,5,0)!=1) return 4;
 for(unsigned i=0;i<sizeof(kernels)/sizeof(kernels[0]);i++) for(unsigned taken=0;taken<2;taken++) {
  Kernel k=kernels[i];uint64_t flags=0;unsigned found=0;
  for(unsigned f=0;f<64;f++) if(predicate(k.condition,seed(f))==(int)taken) {flags=seed(f);found=1;break;}
  if(!found) return 5;
  for(unsigned address=0;address<7;address++) for(int native=1;native>=0;native--) {
   int want=address==2||address==3||address==4;
   int got=observe(native?k.original:k.translated,k.width,address,flags);count++;
   if(got!=want) {fprintf(stderr,"kernel%%u width%%u taken%%u address%%u native%%u got%%d want%%d\n",i,k.width,taken,address,native,got,want);return 1;}
  }
 }
 printf("cmov live/dead kernels %%zu translated/original fault outcomes %%u false/live/dead tripwires 4 failures 0\n",sizeof(kernels)/sizeof(kernels[0]),count);
 return 0;
}
`
