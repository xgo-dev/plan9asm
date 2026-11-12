//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86WordMultiplyAddNativeMemoryStatus(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var assembly, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for i, row := range []struct {
		instruction string
		width       int
	}{
		{"PMADDWL (BX),X0", 16},
		{"VPMADDWD.Z (BX),X0,K1,X1", 16},
		{"VPMADDWD.Z (BX),Y0,K1,Y1", 32},
		{"VPMADDWD.Z (BX),Z0,K1,Z1", 64},
		{"PMADDUBSW (BX),X0", 16},
		{"VPMADDUBSW.Z (BX),X0,K1,X1", 16},
		{"VPMADDUBSW.Z (BX),Y0,K1,Y1", 32},
		{"VPMADDUBSW.Z (BX),Z0,K1,Z1", 64},
	} {
		name := fmt.Sprintf("wordmaddfault%d", i)
		// Deliberately discard the computed result. Sideeffect/volatile reads
		// must remain after O2, even with the constant zero K mask.
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-8\nMOVQ input+0(FP),BX\nVPXORD Z0,Z0,Z0\nMOVL $0,CX\nKMOVQ CX,K1\n%s\nRET\n", name, row.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		}}}
		fmt.Fprintf(&declarations, "extern void %s(const uint8_t*);\n", name)
		reference := fmt.Sprintf("read%d", row.width)
		if i == 0 {
			reference = "originalPMADDWD"
		} else if i == 4 {
			reference = "originalPMADDUBSW"
		}
		fmt.Fprintf(&checks, "for(int offset=0;offset<16;++offset) if(compareStatus(%s,%s,memory+offset)) return 1;\n", reference, name)
		fmt.Fprintf(&checks, "if(compareStatus(%s,%s,0) || compareStatus(%s,%s,boundary-%d+1) || compareStatus(%s,%s,boundary-%d)) return 1;\n", reference, name, reference, name, row.width, reference, name, row.width)
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + `
__attribute__((noinline)) static void originalPMADDWD(const uint8_t *p) {
 typedef int32_t V __attribute__((vector_size(16)));
 V carrier={0,0,0,0};
 // This is the original PMADDWD memory opcode, not MOVDQA plus PMADDWD.
 __asm__ volatile("pmaddwd (%1),%0" : "+x"(carrier) : "r"(p) : "memory");
}
__attribute__((noinline)) static void originalPMADDUBSW(const uint8_t *p) {
 typedef int32_t V __attribute__((vector_size(16)));
 V carrier={0,0,0,0};
 __asm__ volatile("pmaddubsw (%1),%0" : "+x"(carrier) : "r"(p) : "memory");
}
__attribute__((noinline)) static void read16(const uint8_t *p) {for(int i=0;i<16;++i) (void)((const volatile uint8_t*)p)[i];}
__attribute__((noinline)) static void read32(const uint8_t *p) {for(int i=0;i<32;++i) (void)((const volatile uint8_t*)p)[i];}
__attribute__((noinline)) static void read64(const uint8_t *p) {for(int i=0;i<64;++i) (void)((const volatile uint8_t*)p)[i];}
typedef struct {int signal;int code;} Status;
static int observe(void (*program)(const uint8_t*),const uint8_t *input,Status *out) {
 pid_t child=fork(); if(child<0) return 1;
 if(child==0) {
  struct rlimit limit={0,0}; if(setrlimit(RLIMIT_CORE,&limit)) _exit(3);
  program(input); _exit(0);
 }
 int status=0; if(waitpid(child,&status,0)!=child) return 1;
 if(WIFSIGNALED(status)) {*out=(Status){WTERMSIG(status),0};return 0;}
 if(WIFEXITED(status)) {*out=(Status){0,WEXITSTATUS(status)};return 0;}
 return 1;
}
static int compareStatus(void (*original)(const uint8_t*),void (*translated)(const uint8_t*),const uint8_t *input) {
 Status a,b;
 if(observe(original,input,&a) || observe(translated,input,&b)) return 1;
 if(a.signal!=b.signal || a.code!=b.code) {
  fprintf(stderr,"input=%p mod16=%lu original=(%d,%d) translated=(%d,%d)\n",input,(unsigned long)((uintptr_t)input%16),a.signal,a.code,b.signal,b.code); return 1;
 }
 return 0;
}
int main(void) {
 long page=sysconf(_SC_PAGESIZE); if(page<=0 || page%64) return 1;
 uint8_t *memory=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED) return 1;
 memset(memory,0x83,(size_t)page);
 if(mprotect(memory,(size_t)page,PROT_READ) || mprotect(memory+page,(size_t)page,PROT_NONE)) return 1;
 uint8_t *boundary=memory+page;
` + checks.String() + `
 if(munmap(memory,(size_t)page*2)) return 1;
 return 0;
}
`
	for _, opt := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", opt), func(t *testing.T) {
			text := ir
			if opt {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "word-madd-read-status", triple, text, main, prefix)
		})
	}
	t.Log("legacy exact opcode original/translated typed status at each mod16 and real guard-page boundaries; EVEX zero-mask full-read contract uses independent volatile reader, not unexecuted AVX512 hardware as oracle")
}
