//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute only first-party, initialized storage. The original reference uses
// actual stock-Go opcode bytes, not a compiler intrinsic or reconstructed math.
// Rosetta is a diagnostic transport; required Linux/amd64 executes this root.
func TestCrossLinuxRuntimeMatrixX86LegacyLogicalMemoryOriginalFaultsAndBytes(t *testing.T) {
	x86LegacyLogicalMemoryRuntime(t, false)
}

func x86LegacyLogicalMemoryRuntime(t *testing.T, nativeAlignment bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, kernels, checks strings.Builder
	signatures := map[string]FuncSig{}
	for index, name := range x86LegacyLogicalMemoryNames {
		code := x86LegacyLogicalOriginalBytes(t, "amd64", name)
		literal := make([]string, len(code))
		for i, value := range code {
			literal[i] = fmt.Sprintf("0x%02x", value)
		}
		fmt.Fprintf(&kernels, `
static __attribute__((noinline)) void original%d(uint8_t *out,const uint8_t *a,const uint8_t *b) {
 __asm__ volatile("movups (%%1),%%%%xmm0\n\tstc\n\t.byte %s\n\tmovups %%%%xmm0,(%%2)\n\tsetc 16(%%2)"
  : : "a"(a),"r"(b),"r"(out) : "xmm0","memory","cc");
}
`, index, strings.Join(literal, ","))
		for _, dead := range []bool{false, true} {
			fn := fmt.Sprintf("logical%d_%t", index, dead)
			fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVUPS (CX),X0\nSTC\n%s (BX),X0\n", fn, name)
			if !dead {
				assembly.WriteString("MOVUPS X0,(AX)\n")
			}
			assembly.WriteString("SETCS 16(AX)\nRET\n")
			signatures[fn] = FuncSig{Name: fn, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
			fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*);\n", fn)
		}
		mode := []int{0, 0, 1, 1, 2, 2, 3, 3, 0, 1, 2, 3}[index]
		fmt.Fprintf(&checks, `{
 if(check_values(original%[1]d,logical%[1]d_false,%[2]d)) return %[3]d;
 for(int kind=%[5]d;kind<3;++kind) {
  int original_fault=observe_fault(original%[1]d,kind);
  if(original_fault!=SIGSEGV && original_fault!=SIGBUS) { fprintf(stderr,"%[4]s original fault kind%%d=%%d\n",kind,original_fault); return %[3]d; }
  if(observe_fault(logical%[1]d_false,kind)!=original_fault || observe_fault(logical%[1]d_true,kind)!=original_fault) return %[3]d;
 }
}
`, index, mode, index+10, name, map[bool]int{false: 1, true: 0}[nativeAlignment])
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: signatures})
	if err != nil {
		t.Fatal(err)
	}
	const helper = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xmmintrin.h>
typedef void (*kernel)(uint8_t*,const uint8_t*,const uint8_t*);
static int observe_fault(kernel call,int kind) {
 _Alignas(16) uint8_t a[48],b[48],out[48];
 memset(a,0x35,sizeof(a)); memset(b,0x71,sizeof(b)); memset(out,0xa7,sizeof(out));
 long page=sysconf(_SC_PAGESIZE);
 if(page<=0) return -3;
 uint8_t *area=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
 if(area==MAP_FAILED) return -4;
 if(mprotect(area+page,(size_t)page,PROT_NONE)) { munmap(area,(size_t)page*2); return -5; }
 pid_t child=fork(); if(child<0) return -1;
 if(!child) {
  struct rlimit no_core={0,0};
  if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
  const uint8_t *source=kind==0?a+1:kind==1?0:area+page;
  call(out+1,source,b+1);
  _exit(91);
 }
 int status=0;
 if(waitpid(child,&status,0)!=child) return -2;
 if(munmap(area,(size_t)page*2)) return -6;
 return WIFSIGNALED(status)?WTERMSIG(status):-(WEXITSTATUS(status)+100);
}
static int check_values(kernel original,kernel translated,int mode) {
 for(int sample=0;sample<257;++sample) for(int rc=0;rc<4;++rc) {
  _Alignas(16) uint8_t a[48],b[48],go[48],llvm[48];
  memset(a,0xa7,sizeof(a)); memset(b,0xb9,sizeof(b));
  memset(go,0xc3,sizeof(go)); memset(llvm,0xc3,sizeof(llvm));
  for(int i=0;i<16;++i) { a[i+16]=(uint8_t)(sample*71+i*19); b[i+1]=(uint8_t)(sample*31-i*59); }
  uint8_t original_a[48],original_b[48]; memcpy(original_a,a,48); memcpy(original_b,b,48);
  uint32_t saved=_mm_getcsr(),csr=0x1f80|(rc<<13)|(sample&63);
  _mm_setcsr(csr); original(go+1,a+16,b+1); uint32_t go_csr=_mm_getcsr();
  _mm_setcsr(csr); translated(llvm+1,a+16,b+1); uint32_t llvm_csr=_mm_getcsr(); _mm_setcsr(saved);
  if(go_csr!=csr || llvm_csr!=csr || memcmp(a,original_a,48) || memcmp(b,original_b,48) || memcmp(go,llvm,48)) return 1;
  if(go[17]!=1) return 2;
  for(int i=0;i<48;++i) if((i<1 || i>17) && go[i]!=0xc3) return 2;
  for(int i=0;i<16;++i) {
   uint8_t x=a[i+16],y=b[i+1],want;
   /* Two PS/PD encodings per operation; the last four are integer aliases. */
   if(mode==0) want=x&y;
   else if(mode==1) want=x&(uint8_t)~y;
   else if(mode==2) want=x|y;
   else if(mode==3) want=x^y;
   else return 3;
   if(go[i+1]!=want) return 4;
  }
 }
 return 0;
}
`
	driver := helper + kernels.String() + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "legacy-logical-native", ir, driver, level)
		})
	}
	t.Logf("12 original memory opcodes: 257×4 initialized byte/CF/MXCSR/canary inputs; live/dead NULL+guard-page faults at O0/O2; native alignment=%t; host=%s/%s", nativeAlignment, runtime.GOOS, runtime.GOARCH)
}

func TestX86LegacyLogicalMemoryFaultChildDisablesCore(t *testing.T) {
	if err := runtimeOracleFaultCorePolicy(runtimeOracleFaultC(t, "amd64_legacy_logical_memory_runtime_unix_test.go")); err != nil {
		t.Fatal(err)
	}
}
