//go:build linux || darwin

package plan9asm

import (
	"fmt"
	"runtime"
	"testing"
)

// This is host-executed Software memory semantics, not original-Go or native
// x87 environment execution. Both live and dead observations must read exactly
// 28 bytes without borrowing the mapped page's extra accessible storage.
func TestX86X87ENVSoftwareLiveDeadGuardPageFootprint(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang are required")
	}
	const driver = `
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern uint16_t EnvRead(uint64_t address);
static int probe(unsigned char *input, int fault) {
  pid_t child=fork();
  if (child<0) return 1;
  if (!child) {
    struct rlimit limit={0,0};
    if (setrlimit(RLIMIT_CORE,&limit)) _exit(3);
    volatile uint16_t value=EnvRead((uint64_t)(uintptr_t)input);
    (void)value;
    _exit(0);
  }
  int status=0;
  pid_t waited;
  do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
  if (waited!=child) return 1;
  return fault ? !(WIFSIGNALED(status) &&
      (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS)) :
      !(WIFEXITED(status) && WEXITSTATUS(status)==0);
}
int main(void) {
  const long page=sysconf(_SC_PAGESIZE);
  if (page<64) return 2;
  unsigned char *area=mmap(0,(size_t)page*3,PROT_READ|PROT_WRITE,
      MAP_PRIVATE|MAP_ANON,-1,0);
  if (area==MAP_FAILED) return 2;
  memset(area+page,0x5a,(size_t)page);
  if (mprotect(area,(size_t)page,PROT_NONE) ||
      mprotect(area+page*2,(size_t)page,PROT_NONE)) return 2;
  unsigned char *end=area+page*2;
  if (probe(area+page,0) || probe(end-28,0) || probe(end-27,1) ||
      probe(area+page-1,1)) {
    fprintf(stderr,"ENV28 live/dead read has an incorrect boundary\n");
    return 1;
  }
  return munmap(area,(size_t)page*3) ? 2 : 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, dead := range []bool{false, true} {
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("dead%t/IR-O2-%t", dead, optimized), func(t *testing.T) {
				ir := x86X87ENVReadIR(t, "", dead)
				if optimized {
					ir = x86MulDivRoundOptimize(t, ir)
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "env28-fault", triple, ir, driver, nil)
			})
		}
	}
}
