//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86LegacyFloatMemoryProgram(t *testing.T, triple string, dead bool) string {
	t.Helper()
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for i, opcode := range x86LegacyFloatMemoryOpcodes() {
		name := fmt.Sprintf("memory%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nVMOVUPS (BX),Z0\n%s (CX),X0\n", name, opcode)
		if !dead {
			source.WriteString("VMOVUPS Z0,(AX)\n")
		}
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}, {Offset: 16, Type: Ptr, Index: 2, Field: -1},
		}}}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

// The independent reference executes each original m128 opcode, rather than
// MOVDQA or a register-only arithmetic substitute. The original physical
// operation supplies the expected typed status, without guessing a vendor,
// emulator, signal mapping, or machine-control setting. The required native
// CI counterpart has the same test root; Rosetta is not native hardware proof.
func TestCrossLinuxRuntimeMatrixX86LegacyPackedFloatingNativeMemory(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var references, table strings.Builder
	for i, opcode := range x86LegacyFloatMemoryOpcodes() {
		fmt.Fprintf(&references, `extern void memory%d(void*,const void*,const void*);
static __attribute__((noinline)) void reference%d(void *out,const void *a,const void *b) {
 uint8_t low[16];
 __asm__ volatile("movups (%%1),%%%%xmm0; %s (%%2),%%%%xmm0; movups %%%%xmm0,(%%0)"::"r"(low),"r"(a),"r"(b):"xmm0","memory");
 memmove(out,a,64);memcpy(out,low,16);
}
`, i, i, strings.ToLower(opcode))
		if i > 0 {
			table.WriteString(",")
		}
		fmt.Fprintf(&table, "{reference%d,memory%d,%d}", i, i, 32+32*(i%2))
	}
	main := `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + references.String() + `
typedef void (*operation)(void*,const void*,const void*);
struct pair {operation original,translated;int bits;};
static const struct pair pairs[]={ ` + table.String() + ` };
struct outcome {int kind,exit_code,signal,core;};
static struct outcome fault(operation fn,const void *b) {
 struct outcome result={0,0,0,0};pid_t pid=fork();if(pid<0)return result;
 if(!pid){struct rlimit limit={0,0};if(setrlimit(RLIMIT_CORE,&limit))_exit(120);
  uint8_t a[64] __attribute__((aligned(16)))={0},out[64];unsigned csr=0x1f80;
  __asm__ volatile("ldmxcsr %0"::"m"(csr));fn(out,a,b);_exit(0);}
 int status;if(waitpid(pid,&status,0)!=pid)return result;
 if(WIFSIGNALED(status)){result.kind=2;result.signal=WTERMSIG(status);result.core=!!WCOREDUMP(status);}
 else if(WIFEXITED(status)){result.kind=1;result.exit_code=WEXITSTATUS(status);}
 return result;
}
static int same_status(struct outcome original,struct outcome translated) {
 if(!original.kind||!translated.kind||original.exit_code||translated.exit_code)return 0;
 return original.kind==translated.kind&&original.exit_code==translated.exit_code&&original.signal==translated.signal&&original.core==translated.core;
}
int main(void) {
 const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1f85,0x9fe0};
 const uint64_t edges32[]={0,0x80000000,1,0x00800000,0x3f800001,0xbf800001,0x7f800000,0xff800000,0x7fc12345,0x7f812345};
 const uint64_t edges64[]={0,0x8000000000000000ULL,1,0x0010000000000000ULL,0x3ff0000000000001ULL,0xbff0000000000001ULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8123456789abcULL,0x7ff0123456789abcULL};
 uint8_t bStorage[96] __attribute__((aligned(16)))={0};
 for(int op=0;op<8;op++) {
  for(int offset=0;offset<16;offset++) {
   struct outcome original=fault(pairs[op].original,bStorage+offset),translated=fault(pairs[op].translated,bStorage+offset);
   if(!same_status(original,translated)){fprintf(stderr,"opcode=%d mod16=%d original=%d/%d/%d/%d translated=%d/%d/%d/%d\n",op,offset,original.kind,original.exit_code,original.signal,original.core,translated.kind,translated.exit_code,translated.signal,translated.core);return 1;}
  }
#if !DEAD_RESULT
  for(int round=0;round<4;round++)for(int control=0;control<6;control++)for(int edge=0;edge<10;edge++)for(int alias=0;alias<3;alias++) {
   uint8_t a[64] __attribute__((aligned(16))),b[64] __attribute__((aligned(16))),original[66],translated[66];
   for(int j=0;j<64;j++){a[j]=(uint8_t)(j*13+edge);b[j]=0xb7;}
   const uint64_t *edges=pairs[op].bits==32?edges32:edges64;int bytes=pairs[op].bits/8;
   for(int lane=0;lane<16/bytes;lane++){memcpy(a+lane*bytes,&edges[(edge+lane)%10],bytes);memcpy(b+lane*bytes,&edges[(edge+lane+3)%10],bytes);}
   memset(original,0xc3,66);memset(translated,0xc3,66);
   unsigned csr=controls[control]|(round<<13),expected,actual;
   uint8_t originalA[64] __attribute__((aligned(16))),originalB[64] __attribute__((aligned(16))),translatedA[64] __attribute__((aligned(16))),translatedB[64] __attribute__((aligned(16)));
   memcpy(originalA,a,64);memcpy(originalB,b,64);memcpy(translatedA,a,64);memcpy(translatedB,b,64);
   void *originalOut=alias==1?originalA:alias==2?originalB:original+1,*translatedOut=alias==1?translatedA:alias==2?translatedB:translated+1;
   __asm__ volatile("ldmxcsr %0"::"m"(csr));pairs[op].original(originalOut,originalA,originalB);__asm__ volatile("stmxcsr %0":"=m"(expected));
   __asm__ volatile("ldmxcsr %0"::"m"(csr));pairs[op].translated(translatedOut,translatedA,translatedB);__asm__ volatile("stmxcsr %0":"=m"(actual));
   if(alias){memcpy(original+1,originalOut,64);memcpy(translated+1,translatedOut,64);}
   if(memcmp(original,translated,66)||expected!=actual){fprintf(stderr,"opcode=%d round=%d control=%d edge=%d CSR=%x/%x\n",op,round,control,edge,expected,actual);return 3;}
   if(memcmp(originalA,translatedA,64)||memcmp(originalB,translatedB,64)||(!alias&&(memcmp(translatedA,a,64)||memcmp(translatedB,b,64))))return 8;
  }
#endif
 }
 long page=sysconf(_SC_PAGESIZE);if(page<128)return 4;
 uint8_t *region=mmap(0,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(region==MAP_FAILED||mprotect(region+page,page,PROT_NONE))return 5;
 for(int op=0;op<8;op++)for(int extent=0;extent<=16;extent++) {
  const void *pointer=region+page-extent;struct outcome original=fault(pairs[op].original,pointer),translated=fault(pairs[op].translated,pointer);
  if(!same_status(original,translated)){fprintf(stderr,"guard opcode=%d extent=%d original=%d/%d/%d/%d translated=%d/%d/%d/%d\n",op,extent,original.kind,original.exit_code,original.signal,original.core,translated.kind,translated.exit_code,translated.signal,translated.core);return 6;}
 }
 if(munmap(region,2*page))return 7;
 unsigned csr=0x1f80;__asm__ volatile("ldmxcsr %0"::"m"(csr));return 0;
}
`
	for _, dead := range []bool{false, true} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("dead=%t/O2=%t", dead, optimized), func(t *testing.T) {
				ir := x86LegacyFloatMemoryProgram(t, triple, dead)
				if optimized {
					ir = x86MulDivRoundOptimize(t, ir)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy-float-memory", triple, ir, fmt.Sprintf("#define DEAD_RESULT %d\n", x86FloatAddSubBoolInt(dead))+main, prefix)
			})
		}
	}
}
