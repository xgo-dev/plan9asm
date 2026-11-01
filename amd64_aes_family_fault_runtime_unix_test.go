//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86AESFamilyLiveDeadFaultEnvelopes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, prototypes, originals, rows strings.Builder
	declarations.WriteString("package aesfault\n")
	count, outcomes := 0, 0
	for _, name := range x86AESOracleNames {
		legacy := !strings.HasPrefix(name, "V")
		widths := []int{16}
		if !legacy && !strings.Contains(name, "IMC") && !strings.Contains(name, "KEYGEN") {
			widths = append(widths, 32, 64)
		}
		for _, width := range widths {
			for _, dead := range []bool{false, true} {
				fn := fmt.Sprintf("F%d", count)
				count++
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				row, destination := x86AESOracleRow(name, "(DI)", bank)
				store := ""
				if !dead {
					store = fmt.Sprintf("MOVQ out+8(FP),SI\nVMOVUPS %s%d,(SI)\n", bank, destination)
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DI\nVPXORD Z1,Z1,Z1\n%s\n%sRET\n", fn, row, store)
				fmt.Fprintf(&declarations, "func %s(p *[64]byte,out *[64]byte)\n", fn)
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint8_t*);\n", fn)
				original := "NULL"
				legacyInt := 0
				if legacy {
					legacyInt = 1
					original = "Original" + fn
					nativeStore := ""
					if !dead {
						nativeStore = fmt.Sprintf("MOVOU X%d,(SI)\n", destination)
					}
					actual := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\nPXOR X1,X1\n"+row+"\n"+nativeStore+"RET\n")
					var encoded []string
					for _, value := range actual {
						encoded = append(encoded, fmt.Sprintf("0x%02x", value))
					}
					symbol := original
					if strings.Contains(execution.triple, "apple") {
						symbol = "_" + symbol
					}
					fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(encoded, ",")+"\n")
					fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint8_t*);\n", original)
					outcomes += 9
				}
				outcomes += 9
				fmt.Fprintf(&rows, "{%s,%s,%d,%d},\n", fn, original, width, legacyInt)
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir := x86NarrowOracleIR(t, source.String(), declarations.String(), execution.triple)
	// Rosetta is a differential diagnostic, not the native alignment oracle.
	// The Linux AMD64 owner must additionally enforce the architectural fault.
	nativeAlignment := runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
	reference := fmt.Sprintf("#define NATIVE_ALIGNMENT %d\n", x86FloatAddSubBoolInt(nativeAlignment)) +
		fmt.Sprintf(x86AESFaultC, prototypes.String(), originals.String(), rows.String())
	for _, pipeline := range []struct{ name, backend, ir string }{{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)}} {
		t.Run(pipeline.name, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "aes-fault", pipeline.ir, reference, pipeline.backend)
			want := fmt.Sprintf("aes live/dead kernels %d exact fault outcomes %d tripwires 4 failures 0\n", count, outcomes)
			if string(output) != want {
				t.Fatal("AES original/native-width/dead-read faults", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

const x86AESFaultC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#ifndef ALIGNMENT_OBSERVED
#define ALIGNMENT_OBSERVED(kernel,address,fault) ((void)0)
#endif
%s
%s
typedef void(*Program)(const uint8_t*,uint8_t*);
typedef struct {Program translated,original;unsigned width,legacy;} Kernel;
static Kernel kernels[]={%s};
static int observe(Program p,unsigned width,unsigned address){
 pid_t child=fork();if(child<0)return -1;
 if(child==0){
  struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core))_exit(120);
  _Alignas(64) uint8_t data[128],out[64];memset(data,0xa7,sizeof(data));const uint8_t *input=data;
  if(address==1)input++;
  if(address==2)input=NULL;
  if(address>=3){long page=sysconf(_SC_PAGESIZE);if(page<=0)_exit(121);
   uint8_t *memory=mmap(NULL,2*(size_t)page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(memory==MAP_FAILED)_exit(122);
   memset(memory,0xa7,2*(size_t)page);
   if(address<7){if(mprotect(memory+page,(size_t)page,PROT_NONE))_exit(123);
    unsigned available[]={0,width-1,width,width+1};input=memory+page-available[address-3];
   }else{if(mprotect(memory,(size_t)page,PROT_NONE))_exit(123);input=memory+page-(address==7?4:12);}
  }
  p(input,out);_exit(0);
 }
 int status=0;if(waitpid(child,&status,0)!=child)return -2;
 if(WIFEXITED(status))return WEXITSTATUS(status)?-3:0;
 if(WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS))return 1;
 return -4;
}
static void missing(const uint8_t*p,uint8_t*out){(void)p;(void)out;}
static void short_read(const uint8_t*p,uint8_t*out){out[0]=*(volatile const uint8_t*)p;}
static void over_read(const uint8_t*p,uint8_t*out){out[0]=*((volatile const uint8_t*)p+63);}
static void missing_prefix(const uint8_t*p,uint8_t*out){out[0]=*((volatile const uint8_t*)p+4)^*((volatile const uint8_t*)p+12);}
int main(void){unsigned count=0;
 if(observe(missing,16,2)!=0||observe(short_read,64,4)!=0||observe(over_read,16,5)!=1||observe(missing_prefix,16,7)!=0)return 4;
 for(unsigned i=0;i<sizeof(kernels)/sizeof(kernels[0]);i++)for(unsigned a=0;a<9;a++){
  Kernel k=kernels[i];int want=a==2||a==3||a==4||a>=7;
  // Intel SDM Table 2-21: legacy SSE memory operands retain #GP for a
  // non-16-byte-aligned address; VEX/EVEX do not inherit that exception.
  int unaligned=k.legacy&&(a==1||a==6);
  if(unaligned&&NATIVE_ALIGNMENT)want=1;
  for(int original=1;original>=0;original--){if(original&&!k.original)continue;
   int got=observe(original?k.original:k.translated,k.width,a);count++;
   // Diagnostic hosts still require exact original/translated agreement.
   if(original&&unaligned&&!NATIVE_ALIGNMENT&&(got==0||got==1)){
    want=got;ALIGNMENT_OBSERVED(i,a,got);
   }
   if(got!=want){fprintf(stderr,"AES kernel%%u width%%u address%%u original%%d got%%d want%%d\n",i,k.width,a,original,got,want);return 1;}
  }
 }
 printf("aes live/dead kernels %%zu exact fault outcomes %%u tripwires 4 failures 0\n",sizeof(kernels)/sizeof(kernels[0]),count);return 0;
}
`
