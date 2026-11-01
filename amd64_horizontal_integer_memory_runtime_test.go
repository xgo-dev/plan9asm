//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86HorizontalIntegerOriginalNativeMemory(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, originals, checks strings.Builder
	sigs := map[string]FuncSig{}
	// This independent list fixes the original SSSE3 bytes and arithmetic;
	// neither native oracle nor expected values consume the production spec.
	for index, entry := range []struct {
		op                    string
		opcode                byte
		lane, subtract, clamp int
	}{
		{"PHADDW", 1, 2, 0, 0}, {"PHADDD", 2, 4, 0, 0}, {"PHADDSW", 3, 2, 0, 1},
		{"PHSUBW", 5, 2, 1, 0}, {"PHSUBD", 6, 4, 1, 0}, {"PHSUBSW", 7, 2, 1, 1},
	} {
		code := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+entry.op+" (SI),X1\nRET\n")
		if !bytes.Equal(code, []byte{0x66, 0x0f, 0x38, entry.opcode, 0x0e, 0xc3}) {
			t.Fatalf("original horizontal m128 bytes changed: %s %x", entry.op, code)
		}
		for _, dead := range []bool{false, true} {
			name := fmt.Sprintf("horizontalmemory%d_%t", index, dead)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ out+0(FP),AX\nMOVQ input+8(FP),BX\nMOVOU (AX),X1\nCMPQ BX,BX\nSTC\n%s (BX),X1\n", name, entry.op)
			tail := ""
			if !dead {
				source.WriteString("MOVOU X1,16(AX)\n")
				tail = "; movdqu %%xmm1,16(%%rdi)"
			}
			source.WriteString("SETCS 32(AX)\nSETNE 33(AX)\nSTMXCSR 36(AX)\nRET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*);\n", name)
			fmt.Fprintf(&originals, `static void original_%s(uint8_t *out,const uint8_t *input) {
 __asm__ volatile("movdqu (%%%%rdi),%%%%xmm1; cmpq %%%%rsi,%%%%rsi; stc; .byte 0x66,0x0f,0x38,0x%02x,0x0e%s; setc 32(%%%%rdi); setnz 33(%%%%rdi); stmxcsr 36(%%%%rdi)" ::
  "D"(out),"S"(input) : "xmm1","cc","memory");
}
`, name, entry.opcode, tail)
			fmt.Fprintf(&checks, `
 if(compare(original_%[1]s,%[1]s,region,0,%[2]d,%[3]d,%[4]d,%[5]d) ||
    compare(original_%[1]s,%[1]s,boundary-16,0,%[2]d,%[3]d,%[4]d,%[5]d) ||
    compare(original_%[1]s,%[1]s,region+1,alignmentFault,%[2]d,%[3]d,%[4]d,%[5]d) ||
    compare(original_%[1]s,%[1]s,boundary-15,1,%[2]d,%[3]d,%[4]d,%[5]d) ||
    compare(original_%[1]s,%[1]s,0,1,%[2]d,%[3]d,%[4]d,%[5]d)) return 1;
`, name, entry.lane, entry.subtract, entry.clamp, x86FloatAddSubBoolInt(dead))
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + originals.String() + `
typedef void (*memoryfn)(uint8_t*,const uint8_t*);
static int64_t laneValue(const uint8_t *p,int lane) {
 if(lane==2) {int16_t v;memcpy(&v,p,2);return v;}
 int32_t v;memcpy(&v,p,4);return v;
}
static int observe(memoryfn fn,const uint8_t *input,int lane,int sub,int clamp,int dead) {
 pid_t child=fork();
 if(child<0) return -1;
 if(child==0) {
  struct rlimit limit={0,0};
  if(setrlimit(RLIMIT_CORE,&limit)) _exit(2);
  uint8_t out[48],expected[48];unsigned csr,after;
  for(unsigned i=0;i<sizeof(out);i++) out[i]=(uint8_t)(i*79+113);
  memcpy(expected,out,sizeof(out));
  __asm__ volatile("stmxcsr %0":"=m"(csr));
  fn(out+1,input);
  if(!dead) {
   for(int i=0;i<16/lane;i++) {
    const uint8_t *a=i<8/lane ? expected+1 : input;
    int at=2*(i%(8/lane))*lane;
    int64_t left=laneValue(a+at,lane),right=laneValue(a+at+lane,lane);
    int64_t value=sub ? left-right : left+right;
    if(clamp) {if(value<-32768)value=-32768;if(value>32767)value=32767;}
    uint64_t bits=(uint64_t)value;
    for(int byte=0;byte<lane;byte++) expected[17+i*lane+byte]=(uint8_t)(bits>>(8*byte));
   }
  }
  expected[33]=1;expected[34]=0;memcpy(expected+37,&csr,4);
  __asm__ volatile("stmxcsr %0":"=m"(after));
  if(memcmp(out,expected,sizeof(out)) || after!=csr) _exit(3);
  _exit(0);
 }
 int status;
 if(waitpid(child,&status,0)!=child) return -1;
 if(WIFEXITED(status)) return WEXITSTATUS(status);
 if(WIFSIGNALED(status)) return 128+WTERMSIG(status);
 return -1;
}
static int compare(memoryfn reference,memoryfn translated,const uint8_t *input,int fault,int lane,int sub,int clamp,int dead) {
 int native=observe(reference,input,lane,sub,clamp,dead),got=observe(translated,input,lane,sub,clamp,dead);
 int memoryFault=native==128+SIGSEGV || native==128+SIGBUS;
 int valid=fault==1 ? memoryFault : fault==-1 ? native==0 || memoryFault : native==0;
 if(native<0 || native!=got || !valid) {
  fprintf(stderr,"horizontal native=%d LLVM=%d input=%p fault=%d lane=%d sub=%d clamp=%d dead=%d\n",native,got,input,fault,lane,sub,clamp,dead);
  return 1;
 }
 return 0;
}
int main(void) {
 long page=sysconf(_SC_PAGESIZE);
 if(page<64) return 1;
 uint8_t *region=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(region==MAP_FAILED || mprotect(region+page,(size_t)page,PROT_NONE)) return 1;
 for(long i=0;i<page;i++) region[i]=(uint8_t)(i*31+97);
 uint8_t *boundary=region+page;
#if defined(__linux__)
 int alignmentFault=1;
#else
 int alignmentFault=-1;
#endif
` + checks.String() + `
 return munmap(region,(size_t)page*2)!=0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "horizontal-original-memory", triple, text, oracle, prefix)
		})
	}
	t.Log("12 original Go-byte/LLVM legacy live/dead programs, aligned/unaligned/NULL/guard-page reads, whole results, flags, MXCSR and canaries; Rosetta is diagnostic")
}

func TestCrossLinuxRuntimeMatrixX86HorizontalIntegerVEXDeadFullReads(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, opcode := range []string{"VPHADDW", "VPHADDD", "VPHADDSW", "VPHSUBW", "VPHSUBD", "VPHSUBSW"} {
		for width, bank := range []string{"X", "Y"} {
			name := fmt.Sprintf("horizontalread%d_%d", index, width)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ input+0(FP),BX\nVPXOR %s0,%s0,%s0\n%s (BX),%s0,%s1\nRET\n", name, bank, bank, bank, opcode, bank, bank)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
			fmt.Fprintf(&declarations, "extern void %s(const uint8_t*);\n", name)
			fmt.Fprintf(&checks, "if(check(%s,0,1) || check(%s,boundary-%d+1,1) || check(%s,boundary-%d,0)) return 1;\n", name, name, 16<<width, name, 16<<width)
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	oracle := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + `
static int check(void (*program)(const uint8_t*),const uint8_t *input,int fault) {
 pid_t child=fork();if(child<0)return 1;
 if(child==0) {struct rlimit limit={0,0};if(setrlimit(RLIMIT_CORE,&limit))_exit(2);program(input);_exit(0);}
 int status;if(waitpid(child,&status,0)!=child)return 1;
 int got=WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS);
 if(fault ? !got : !WIFEXITED(status) || WEXITSTATUS(status)!=0) {
  fprintf(stderr,"horizontal dead read input=%p fault=%d status=%x\n",input,fault,status);return 1;
 }
 return 0;
}
int main(void) {
 long page=sysconf(_SC_PAGESIZE);if(page<=0)return 1;
 uint8_t *memory=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED || mprotect(memory+page,(size_t)page,PROT_NONE))return 1;
 uint8_t *boundary=memory+page;
` + checks.String() + `return munmap(memory,(size_t)page*2)!=0;}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "horizontal-vex-dead-full-read", triple, text, oracle, prefix)
		})
	}
}
