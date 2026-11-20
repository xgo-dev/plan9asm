//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedSubtractNativeMemoryStatus(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, references, checks strings.Builder
	sigs := map[string]FuncSig{}
	index := 0
	for _, original := range x86PackedSubtractCallerRows() {
		parsed, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+original+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		instruction := parsed.Funcs[0].Instrs[1]
		form, _, err := x86PackedSubtractProperties(instruction, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		if form.memory < 0 || form.mask >= 0 && !form.zeroing {
			continue
		}
		masks := []int{0}
		if form.mask >= 0 {
			masks = []int{0, 1}
		}
		for _, mask := range masks {
			name := fmt.Sprintf("packedsubtractfault%d", index)
			reference := fmt.Sprintf("subtractReference%d", index)
			index++
			row := strings.ReplaceAll(original, "(DI)", "(BX)")
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ input+0(FP),BX\n"+
				"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n"+
				"VPXORD Z15,Z15,Z15\nVPXORD Z21,Z21,Z21\nVPXORD Z22,Z22,Z22\n"+
				"MOVL $%d,CX\nKMOVQ CX,K1\n%s\nRET\n", name, mask, row)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
			fmt.Fprintf(&declarations, "extern void %s(const uint8_t*);\n", name)
			if form.legacy {
				mnemonic := strings.ToLower(string(instruction.Op))
				if mnemonic == "psubl" {
					mnemonic = "psubd"
				}
				fmt.Fprintf(&references, "__attribute__((noinline)) static void %s(const uint8_t *p) {\n"+
					" typedef int32_t V __attribute__((vector_size(16)));\n V value = {0,0,0,0};\n"+
					" __asm__ volatile(\"%s (%%1),%%0\" : \"+x\"(value) : \"r\"(p) : \"memory\");\n}\n",
					reference, mnemonic)
			} else {
				bytes := form.memoryBytes
				if form.mask >= 0 {
					bytes = 0
					if mask != 0 {
						bytes = form.laneBits / 8
					}
				}
				fmt.Fprintf(&references, "__attribute__((noinline)) static void %s(const uint8_t *p) {\n"+
					" for (int i = 0; i < %d; ++i) {\n  (void)((const volatile uint8_t*)p)[i];\n }\n}\n",
					reference, bytes)
			}
			fmt.Fprintf(&checks, "for(int n=0;n<16;++n) {\n if(compare(%s,%s,memory+n)) return 1;\n}\n", reference, name)
			for _, offset := range []int{0, 1, form.laneBits / 8, 16, 32, 64} {
				fmt.Fprintf(&checks, "if(compare(%s,%s,boundary-%d)) return 1;\n", reference, name, offset)
			}
			fmt.Fprintf(&checks, "if(compare(%s,%s,0)) return 1;\n", reference, name)
		}
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
	main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + declarations.String() + references.String() + `
typedef struct { int signal; int code; } Status;

static int observe(void (*fn)(const uint8_t*), const uint8_t *p, Status *out) {
 pid_t child = fork();
 if (child < 0) return 1;
 if (child == 0) {
  struct rlimit limit = {0,0};
  if (setrlimit(RLIMIT_CORE,&limit)) _exit(3);
  fn(p);
  _exit(0);
 }
 int status;
 if (waitpid(child,&status,0) != child) return 1;
 if (WIFSIGNALED(status)) {
  *out = (Status){WTERMSIG(status),0};
  return 0;
 }
 if (WIFEXITED(status)) {
  *out = (Status){0,WEXITSTATUS(status)};
  return 0;
 }
 return 1;
}

static int compare(void (*original)(const uint8_t*),
                   void (*translated)(const uint8_t*), const uint8_t *p) {
 Status a, b;
 if (observe(original,p,&a) || observe(translated,p,&b)) return 1;
 if (a.signal != b.signal || a.code != b.code) {
  fprintf(stderr,"pointer=%p mod16=%lu original=(%d,%d) translated=(%d,%d)\n",
          p,(unsigned long)((uintptr_t)p%16),a.signal,a.code,b.signal,b.code);
  return 1;
 }
 return 0;
}

int main(void) {
 long page = sysconf(_SC_PAGESIZE);
 if (page <= 0 || page%64) return 1;
 uint8_t *memory = mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANON,-1,0);
 if (memory == MAP_FAILED) return 1;
 memset(memory,0x87,(size_t)page);
 if (mprotect(memory,(size_t)page,PROT_READ) ||
     mprotect(memory+page,(size_t)page,PROT_NONE)) return 1;
 uint8_t *boundary = memory+page;
` + checks.String() + `
 if (munmap(memory,(size_t)page*2)) return 1;
 return 0;
}
`
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-subtract-fault", triple, text, main, prefix)
		})
	}
	t.Logf("%d dead-output memory programs at every mod16/NULL/RO guard; native original SSE and independent E4 reads at O0/O2, not AVX512 hardware", index)
}
