//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86PackedWrappingAddNativeMemoryStatus(t *testing.T) {
	x86PackedAddNativeMemoryStatus(t, x86WrappingAddOpcodes, []int{8, 16, 32, 64, 8, 16, 32, 64})
}

func TestCrossLinuxRuntimeMatrixX86PackedSaturatingAddNativeMemoryStatus(t *testing.T) {
	x86PackedAddNativeMemoryStatus(t, []string{
		"PADDSB", "PADDSW", "PADDUSB", "PADDUSW",
		"VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW",
	}, []int{8, 16, 8, 16, 8, 16, 8, 16})
}

func x86PackedAddNativeMemoryStatus(t *testing.T, opcodes []string, laneBits []int) {
	t.Helper()
	if len(opcodes) != len(laneBits) {
		t.Fatal("opcode/lane inventory differs")
	}
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, references, checks strings.Builder
	sigs := map[string]FuncSig{}
	index := 0
	for opcodeIndex, opcode := range opcodes {
		legacy := !strings.HasPrefix(opcode, "V")
		bits := laneBits[opcodeIndex]
		modes := []int{-1}
		if !legacy {
			modes = []int{-1, 0, 1}
		}
		for _, mode := range modes {
			name := fmt.Sprintf("packedaddfault%d", index)
			index++
			row := opcode + " (BX),X0"
			if !legacy {
				row = opcode + " (BX),Z0,Z1"
				if mode >= 0 {
					row = opcode + ".Z (BX),Z0,K1,Z1"
				}
			}
			mask := mode
			if mask < 0 {
				mask = 0
			}
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-8\nMOVQ input+0(FP),BX\nVPXORD Z0,Z0,Z0\nMOVL $%d,CX\nKMOVQ CX,K1\n%s\nRET\n", name, mask, row)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}
			fmt.Fprintf(&declarations, "extern void %s(const uint8_t*);\n", name)
			reference := fmt.Sprintf("reference%d", index)
			if legacy {
				mnemonic := strings.ToLower(opcode)
				if mnemonic == "paddl" {
					mnemonic = "paddd"
				}
				fmt.Fprintf(&references, "__attribute__((noinline)) static void %s(const uint8_t*p){typedef int32_t V __attribute__((vector_size(16)));V v={0,0,0,0};__asm__ volatile(\"%s (%%1),%%0\":\"+x\"(v):\"r\"(p):\"memory\");}\n", reference, mnemonic)
			} else {
				width := 64
				if mode == 0 {
					width = 0
				} else if mode == 1 {
					width = bits / 8
				}
				fmt.Fprintf(&references, "__attribute__((noinline)) static void %s(const uint8_t*p){for(int i=0;i<%d;++i)(void)((const volatile uint8_t*)p)[i];}\n", reference, width)
			}
			fmt.Fprintf(&checks, "for(int n=0;n<16;++n)if(compare(%s,%s,memory+n))return 1;\n", reference, name)
			for _, offset := range []int{0, 1, bits / 8, 16, 64} {
				fmt.Fprintf(&checks, "if(compare(%s,%s,boundary-%d))return 1;\n", reference, name, offset)
			}
			fmt.Fprintf(&checks, "if(compare(%s,%s,0))return 1;\n", reference, name)
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
typedef struct {int signal;int code;} Status;
static int observe(void(*fn)(const uint8_t*),const uint8_t*p,Status*out){
 pid_t child=fork();if(child<0)return 1;
 if(child==0){struct rlimit limit={0,0};if(setrlimit(RLIMIT_CORE,&limit))_exit(3);fn(p);_exit(0);}
 int status;if(waitpid(child,&status,0)!=child)return 1;
 if(WIFSIGNALED(status)){*out=(Status){WTERMSIG(status),0};return 0;}
 if(WIFEXITED(status)){*out=(Status){0,WEXITSTATUS(status)};return 0;}return 1;
}
static int compare(void(*original)(const uint8_t*),void(*translated)(const uint8_t*),const uint8_t*p){
 Status a,b;if(observe(original,p,&a)||observe(translated,p,&b))return 1;
 if(a.signal!=b.signal||a.code!=b.code){fprintf(stderr,"pointer=%p mod16=%lu original=(%d,%d) translated=(%d,%d)\n",p,(unsigned long)((uintptr_t)p%16),a.signal,a.code,b.signal,b.code);return 1;}return 0;
}
int main(void){
 long page=sysconf(_SC_PAGESIZE);if(page<=0||page%64)return 1;
 uint8_t*memory=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED)return 1;memset(memory,0x87,(size_t)page);
 if(mprotect(memory,(size_t)page,PROT_READ)||mprotect(memory+page,(size_t)page,PROT_NONE))return 1;
 uint8_t*boundary=memory+page;
` + checks.String() + "if(munmap(memory,(size_t)page*2))return 1;return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-add-fault", triple, text, main, prefix)
		})
	}
	t.Log("all four original SSE opcodes typed-status at every mod16/NULL/RO guard; E4/E4.nb zero/active masks observed against independent volatile reads, not unexecuted AVX512 hardware")
}
