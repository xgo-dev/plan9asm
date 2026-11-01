//go:build darwin || linux

package plan9asm

// E4 is element-granular even for dead results. Families independently supply
// every actual source tuple, element width and number of mask-selected lanes.
func x86E4DeadReadFaultOracle(prototypes, metadata string) string {
	return `
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes + `
typedef void (*Kernel)(const uint8_t *,uint64_t);
typedef struct { Kernel run; int extent,lane,lanes; } Row;
static const Row rows[]={
` + metadata + `
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
    uint64_t outside=row->lanes<64?UINT64_C(1)<<row->lanes:0;
    struct {const uint8_t *p;uint64_t mask;int want;} cases[]={
      {0,0,0}, {0,outside,0}, {0,1,1},
      {p+page-row->extent,UINT64_MAX,0},
      {p+page-row->extent+1,UINT64_MAX,1},
      {p+page-row->lane,1,0}, {p+page-row->lane+1,1,1},
    };
    for(unsigned c=0;c<sizeof(cases)/sizeof(cases[0]);c++) {
      int actual=fault(row->run,cases[c].p,cases[c].mask);
      if(actual!=cases[c].want) {
        fprintf(stderr,"blend E4 row=%u case=%u extent=%d actual=%d want=%d\n",
                r,c,row->extent,actual,cases[c].want);
        return 1;
      }
    }
  }
  if(mprotect(p,(size_t)page,PROT_READ)) return 1;
  for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
    if(fault(rows[r].run,p+page-rows[r].extent,UINT64_MAX)) return 1;
  }
  return munmap(p,(size_t)page*2)?1:0;
}
`
}
