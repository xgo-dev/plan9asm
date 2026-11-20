//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86MoveHalfDeadNativeReadsAndWritesKeepExactEightByteFaults(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable guard-page oracle needs its native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	for index, row := range x86MoveHalfOracle {
		for _, write := range []bool{false, true} {
			name, args, store := fmt.Sprintf("DeadHalf%d_%t", index, write), "(AX),X2", 0
			if row.vector {
				args = "(AX),X1,X2"
			}
			if write {
				args, store = "X1,(AX)", 1
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\nMOVQ base+8(FP),BX\n"+
				"VMOVDQU64 (BX),Z1\nVMOVDQU64 Z1,Z2\n%s %s\nRET\n", name, row.op, args)
			fmt.Fprintf(&declarations, "func %s(p *uint64,base *[64]byte)\n", name)
			fmt.Fprintf(&prototypes, "extern void %s(uint64_t *,const uint8_t *);\n", name)
			fmt.Fprintf(&metadata, "{%s,%d},\n", name, store)
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal("complete original dead native half-move source rejected", err)
	}
	for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
		if strings.Count(body, "load volatile i64, ptr") != 8 || strings.Count(body, "store volatile i64 ") != 8 {
			t.Fatal("dead native half-move access was elided or changed width")
		}
	}
	x86ConflictFunnelPortableRuntime(t, llc, clang, "move_half_dead_native", triple, ir,
		fmt.Sprintf(x86MoveHalfDeadMemoryC, prototypes.String(), metadata.String()))
}

const x86MoveHalfDeadMemoryC = `
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
%s
struct row {void (*run)(uint64_t *,const uint8_t *); int write;};
static const struct row rows[]={%s};
static int observe(struct row row,uint8_t *p,const uint8_t *base) {
  pid_t child=fork(); if(child<0) return -1;
  if(!child) {
    struct rlimit limit={0,0}; if(setrlimit(RLIMIT_CORE,&limit)) _exit(120);
    row.run((uint64_t *)p,base); _exit(0);
  }
  int status=0; if(waitpid(child,&status,0)!=child) return -2;
  if(WIFEXITED(status)) return WEXITSTATUS(status)?-3:0;
  return WIFSIGNALED(status)&&(WTERMSIG(status)==SIGSEGV||WTERMSIG(status)==SIGBUS)?1:-4;
}
int main(void) {
  long page=sysconf(_SC_PAGESIZE); if(page<64) return 1;
  uint8_t *p=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  uint8_t *ro=mmap(0,(size_t)page,PROT_READ,MAP_PRIVATE|MAP_ANON,-1,0);
  if(p==MAP_FAILED||ro==MAP_FAILED||mprotect(p+page,(size_t)page,PROT_NONE)) return 1;
  uint8_t base[64]; for(unsigned b=0;b<64;b++) base[b]=(uint8_t)(b*19+7);
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    if(observe(rows[r],0,base)!=1||observe(rows[r],p+page-8,base)!=0||
       observe(rows[r],p+page-7,base)!=1||observe(rows[r],p+1,base)!=0||
       observe(rows[r],ro,base)!=rows[r].write) {fprintf(stderr,"half native row=%%u\n",r);return 2;}
  }
  return munmap(p,(size_t)page*2)||munmap(ro,(size_t)page)?3:0;
}
`
