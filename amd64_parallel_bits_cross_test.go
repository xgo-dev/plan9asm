package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// This name is intentionally included by the required cross-runtime CI regex.
func TestCrossLinuxRuntimeMatrixParallelBits386(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("set PLAN9ASM_CROSS_EXEC=1 for the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"i686-linux-gnu-gcc", "qemu-i386"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", tool, err)
		}
	}
	var source, decl, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		for _, raw := range []bool{false, true} {
			name := fmt.Sprintf("parallel386_%d", index)
			index++
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-12\nMOVL value+0(FP),AX\nMOVL mask+4(FP),BX\n", name)
			line := op + " (BX),AX,CX\n"
			if raw {
				code := assembleX87ControlBytes(t, "386", "TEXT probe(SB),4,$0-0\n"+line+"RET\n")
				for _, b := range code[:len(code)-1] {
					fmt.Fprintf(&source, "BYTE $%#02x\n", b)
				}
			} else {
				source.WriteString(line)
			}
			source.WriteString("MOVL CX,ret+8(FP)\nRET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{I32, Ptr}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}}}
			fmt.Fprintf(&decl, "extern uint32_t %s(uint32_t,const uint32_t *);\n", name)
			deposit := 0
			if strings.HasPrefix(op, "PDEP") {
				deposit = 1
			}
			fmt.Fprintf(&checks, "if(check(%s,mask,%d)) return %d;\n", name, deposit, index)
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
` + decl.String() + `
static void memory_fault(int signal_number) { (void)signal_number; _exit(98); }
static uint32_t reference(uint32_t value,uint32_t mask,int deposit) {
 uint32_t result=0,cursor=1;
 while(mask) {uint32_t low=mask&(-mask);if(deposit ? (value&cursor)!=0 : (value&low)!=0) result|=deposit?low:cursor;mask&=mask-1;cursor<<=1;}
 return result;
}
static int check(uint32_t(*fn)(uint32_t,const uint32_t *),uint32_t *mask,int deposit) {
 uint32_t state=0x9e3779b9;
 for(int i=0;i<256;i++) {
  state^=state<<13;state^=state>>17;state^=state<<5;uint32_t value=state;
  state^=state<<13;state^=state>>17;state^=state<<5;*mask=state;
  if(i==0)*mask=0;if(i==1)*mask=0xffffffffU;if(i>=2&&i<34)*mask=1U<<(i-2);
  if(fn(value,mask)!=reference(value,*mask,deposit)) {fprintf(stderr,"386 parallel bits mismatch case=%d deposit=%d\n",i,deposit);return 1;}
 }
 return 0;
}
int main(void) {
 if(signal(SIGSEGV,memory_fault)==SIG_ERR)return 92;
 long page=sysconf(_SC_PAGESIZE);if(page<4)return 90;
 uint8_t *memory=mmap(0,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(memory==MAP_FAILED||mprotect(memory+page,page,PROT_NONE))return 91;
 uint32_t *mask=(uint32_t *)(memory+page-4);
` + checks.String() + "return munmap(memory,page*2)!=0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc"}, "parallel_bits_386", "i386-unknown-linux-gnu", ir, mainC, []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"})
}
