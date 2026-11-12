package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedShiftLegacyNativeStatusSemantics(t *testing.T) {
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if !rosettaAvailable() {
			t.Fatal("Darwin x86 diagnostic transport required")
		}
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("required Linux original/LLVM native-count counterpart supplies this execution axis")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools required")
	}
	assembly, sigs := x86PackedShiftLegacyMemoryAssembly()
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	driver := x86PackedShiftLegacyCountCHeader + x86PackedShiftLegacyCountDeclarations() +
		x86PackedShiftOriginalCountC() + x86PackedShiftCountCChecks + x86PackedShiftLegacyNativeCountCMain
	compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy_count_status", triple, ir, driver, prefix)
	t.Logf("6 original-opcode/LLVM kernels ×48 numerical inputs, 90 unaligned status comparisons, 6 full128 guard-page fault pairs; transport=%v", prefix)
}

func x86PackedShiftLegacyCountDeclarations() string {
	var source strings.Builder
	for i := range x86LegacyShiftMemoryOpcodes {
		fmt.Fprintf(&source, "extern void legacycount%d(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", i)
	}
	source.WriteString("static legacy_fn kernels[]={legacycount0,legacycount1,legacycount2,legacycount3,legacycount4,legacycount5};\n")
	return source.String()
}

func x86PackedShiftLegacyMemoryAssembly() (string, map[string]FuncSig) {
	var source strings.Builder
	sigs := map[string]FuncSig{}
	for i, operation := range x86LegacyShiftMemoryOpcodes {
		name := fmt.Sprintf("legacycount%d", i)
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-32
MOVQ out+0(FP),AX
MOVQ data+8(FP),BX
MOVQ count+16(FP),CX
MOVQ seed+24(FP),DX
MOVOU (BX),X0
CMPQ DX,$0
JE carry
CMPQ DX,$1
JE overflow
MOVQ $1,DX
CMPQ DX,$0
JMP shifted
carry:
MOVQ $-1,DX
ADDQ $1,DX
JMP shifted
overflow:
MOVQ $0x7fffffffffffffff,DX
ADDQ $1,DX
shifted:
%s (CX),X0
MOVOU X0,(AX)
SETCS 16(AX)
SETOS 17(AX)
SETEQ 18(AX)
SETMI 19(AX)
SETPS 20(AX)
RET
`, name, operation.name)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
	}
	return source.String(), sigs
}

const x86PackedShiftLegacyCountCHeader = `
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
typedef void (*legacy_fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
`

// This independent reference executes the original six physical opcodes. The
// Go object oracle binds each corresponding mnemonic to its original bytes;
// neither this reference nor the math oracle substitutes a different load.
func x86PackedShiftOriginalCountC() string {
	var source strings.Builder
	for i, mnemonic := range []string{"psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq"} {
		fmt.Fprintf(&source, `
static void original%d(uint8_t *out,const uint8_t *data,const uint8_t *count,uint64_t seed) {
 __asm__ volatile(
  "movdqu (%%[data]),%%%%xmm0\n\t"
  "cmpq $0,%%[seed]\n\tje 1f\n\t"
  "cmpq $1,%%[seed]\n\tje 2f\n\t"
  "movq $1,%%%%rax\n\tcmpq $0,%%%%rax\n\tjmp 3f\n\t"
  "1: movq $-1,%%%%rax\n\taddq $1,%%%%rax\n\tjmp 3f\n\t"
  "2: movq $0x7fffffffffffffff,%%%%rax\n\taddq $1,%%%%rax\n\t"
  "3: %s (%%[count]),%%%%xmm0\n\t"
  "movdqu %%%%xmm0,(%%[out])\n\t"
  "setb 16(%%[out])\n\tseto 17(%%[out])\n\tsete 18(%%[out])\n\t"
  "sets 19(%%[out])\n\tsetp 20(%%[out])\n\t"
  : : [out] "r"(out),[data] "r"(data),[count] "r"(count),[seed] "r"(seed)
  : "rax","xmm0","cc","memory");
}
`, i, mnemonic)
	}
	source.WriteString("static legacy_fn originals[]={original0,original1,original2,original3,original4,original5};\n")
	return source.String()
}

// Status observation is independent of the translated implementation. A
// successful child must still satisfy all numerical, flag and canary checks.
const x86PackedShiftCountCChecks = `
static uint64_t read_le(const uint8_t *p,int bytes) {
 uint64_t value=0;
 for(int i=0;i<bytes;i++) value|=(uint64_t)p[i]<<(8*i);
 return value;
}
static int count_memory_fault(int status) {
 if(!WIFSIGNALED(status)) return 0;
 if(WTERMSIG(status)==SIGSEGV) return 1;
#if defined(__APPLE__)
 /* Darwin diagnostic only: require the same original opcode's SIGBUS. */
 if(WTERMSIG(status)==SIGBUS) return 1;
#endif
 return 0;
}
static int check_count(legacy_fn fn,int kernel,int round,int seed,const uint8_t *count) {
 const uint8_t flags[3][5]={{1,0,1,0,1},{0,1,0,1,1},{0,0,0,0,0}};
 uint8_t data[18],out[23],beforeData[18],beforeCount[32];
 for(int i=0;i<18;i++) data[i]=(uint8_t)(i*71+round*97+13);
 memcpy(beforeData,data,18);
 memcpy(beforeCount,count,32);
 memset(out,0xc3,23);
 fn(out+1,data+1,count,(uint64_t)seed);
 if(out[0]!=0xc3 || out[22]!=0xc3 || memcmp(data,beforeData,18) ||
    memcmp(count,beforeCount,32) || memcmp(out+17,flags[seed],5)) return 10+kernel;
 int bytes=(int[]){2,4,8,2,4,8}[kernel];
 uint64_t shift=read_le(count,8);
 for(int i=0;i<16;i+=bytes) {
  uint64_t value=read_le(data+i+1,bytes),want=0;
  if(shift<(uint64_t)(bytes*8)) want=kernel<3?value<<shift:value>>shift;
  for(int b=0;b<bytes;b++) if(out[i+b+1]!=(uint8_t)(want>>(8*b))) return 20+kernel;
 }
 return 0;
}
static int observe_count(legacy_fn fn,int kernel,int round,int seed,const uint8_t *count,int guard) {
 pid_t child=fork();
 if(child<0) return -1;
 if(!child) {
  struct rlimit no_core={0,0};
  if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);

  if(guard) {
   uint8_t data[18],out[23];
   memset(data,13,18); memset(out,0xc3,23);
   fn(out+1,data+1,count,0);
   _exit(90);
  }
  _exit(check_count(fn,kernel,round,seed,count));
 }
 int status=0;
 if(waitpid(child,&status,0)!=child) return -1;
 return status;
}
`

const x86PackedShiftLegacyNativeCountCMain = `
int main(void) {
 const uint64_t counts[]={0,1,7,15,16,17,31,32,33,63,64,65,255,256,UINT64_C(1)<<32,UINT64_MAX};
 for(int kernel=0;kernel<6;kernel++) {
  for(int round=0;round<16;round++) for(int seed=0;seed<3;seed++) {
   _Alignas(16) uint8_t count[32];
   for(int i=0;i<32;i++) count[i]=(uint8_t)(i*31+7);
   for(int i=0;i<8;i++) count[i]=(uint8_t)(counts[round]>>(8*i));
   int original=check_count(originals[kernel],kernel,round,seed,count);
   int translated=check_count(kernels[kernel],kernel,round,seed,count);
   if(original || translated) return 10+kernel;
  }
  for(int offset=1;offset<16;offset++) {
   _Alignas(16) uint8_t count[48];
   memset(count,0x79,sizeof(count));
   memset(count+offset,0,8); count[offset]=1;
   int original=observe_count(originals[kernel],kernel,offset,offset%3,count+offset,0);
   int translated=observe_count(kernels[kernel],kernel,offset,offset%3,count+offset,0);
   int normal=WIFEXITED(original) && WEXITSTATUS(original)==0;
   int fault=count_memory_fault(original);
   if(original<0 || translated<0 || (!normal && !fault) || original!=translated) {
    fprintf(stderr,"legacy kernel=%d mod16=%d original=%x translated=%x\n",kernel,offset,original,translated);
    return 30+kernel;
   }
  }
 }
 size_t page=(size_t)sysconf(_SC_PAGESIZE);
 uint8_t *area=mmap(0,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(area==MAP_FAILED || mprotect(area+page,page,PROT_NONE)) return 40;
 memset(area,7,page);
 for(int kernel=0;kernel<6;kernel++) {
  int original=observe_count(originals[kernel],kernel,0,0,area+page-8,1);
  int translated=observe_count(kernels[kernel],kernel,0,0,area+page-8,1);
  if(original<0 || translated<0 || !count_memory_fault(original) || original!=translated) {
   fprintf(stderr,"legacy full128 kernel=%d original=%x translated=%x\n",kernel,original,translated);
   return 50+kernel;
  }
 }
 if(munmap(area,page*2)) return 60;
 return 0;
}
`
