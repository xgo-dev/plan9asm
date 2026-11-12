//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This checks the translated portable native accesses against independent
// E4/E4NF fault expectations. It is not an original AVX512 execution oracle.
func TestX86ConflictFunnelDeadNativeReadFaults(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable guard-page oracle requires its native 64-bit host counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, metadata strings.Builder
	count := 0
	for _, row := range x86ConflictFunnelRows() {
		for _, broadcast := range []bool{false, true} {
			if broadcast && row.bits == 16 {
				continue
			}
			op := row.op
			bytes := 64
			if broadcast {
				op += ".BCST"
				bytes = row.bits / 8
			}
			op += ".Z"
			instruction := x86ConflictFunnelInstruction(op, "Z", "(AX)", "K1,", row.unary, row.variable)
			name := fmt.Sprint("Dead", count)
			fmt.Fprintf(&declarations, "func %s(p *[64]byte,mask uint64)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),AX\n"+
				"KMOVQ mask+8(FP),K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\nRET\n", name, instruction)
			fmt.Fprintf(&prototypes, "extern void %s(const uint8_t *,uint64_t);\n", name)
			unary := 0
			if row.unary {
				unary = 1
			}
			fmt.Fprintf(&metadata, "{%s,%d,%d,%d},\n", name, bytes, row.bits/8, unary)
			count++
		}
	}
	if count != 24 {
		t.Fatal("incomplete independent dead memory/fault shape inventory", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, "text")
	if err != nil {
		t.Fatal("complete original dead native source rejected", err)
	}
	mainC := `
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + `
typedef void (*Kernel)(const uint8_t *,uint64_t);
typedef struct { Kernel run; int bytes,lane,nf; } Row;
static const Row rows[] = {
` + metadata.String() + `
};
static int fault(Kernel run,const uint8_t *p,uint64_t mask) {
  pid_t child=fork();
  if(child<0) return -1;
  if(!child) {
    struct rlimit no_core={0,0};
    if(setrlimit(RLIMIT_CORE,&no_core)) _exit(120);
    run(p,mask);
    _exit(0);
  }
  int status=0;
  if(waitpid(child,&status,0)!=child) return -2;
  if(WIFEXITED(status)) return WEXITSTATUS(status)==0?0:-3;
  if(WIFSIGNALED(status)) return WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS?1:-4;
  return -5;
}
int main(void) {
  long page=sysconf(_SC_PAGESIZE);
  if(page<64) return 1;
  uint8_t *p=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  if(p==MAP_FAILED || mprotect(p+page,(size_t)page,PROT_NONE)) return 1;
  for(long i=0;i<page;i++) p[i]=(uint8_t)(i*17+3);
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    const Row *row=&rows[r];
    struct {const uint8_t *p;uint64_t mask;int want;} cases[]={
      {0,0,row->nf},
      {0,UINT64_C(1)<<63,row->nf},
      {p+page-row->bytes,UINT64_MAX,0},
      {p+page-row->bytes+1,UINT64_MAX,1},
      {p+page-row->lane,1,row->nf && row->bytes>row->lane},
      {p+page-row->lane+1,1,1},
    };
    for(unsigned c=0;c<sizeof(cases)/sizeof(cases[0]);c++) {
      int actual=fault(row->run,cases[c].p,cases[c].mask);
      if(actual!=cases[c].want) {
        fprintf(stderr,"dead access row=%u case=%u bytes=%d actual=%d want=%d\n",r,c,row->bytes,actual,cases[c].want);
        return 1;
      }
    }
  }
  return munmap(p,(size_t)page*2)?1:0;
}
`
	x86ConflictFunnelPortableRuntime(t, llc, clang, "conflict_funnel_dead_faults", triple, ir, mainC)
}
