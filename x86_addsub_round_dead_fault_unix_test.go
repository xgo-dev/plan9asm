//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Portable 64-bit-host access/fault execution only. Original Go objects are
// observed separately; no original x86 FP/MXCSR or hardware run is implied.
func TestX86AlternatingRoundDeadMemoryTuplesPortable(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("portable pointer64 fault owner requires its Linux/amd64 counterpart TestX86AlternatingRoundDeadMemoryTuplesPortable")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var source, declarations, prototypes, rows strings.Builder
	for index, row := range []struct {
		instruction string
		bytes       int
		second      bool
	}{
		{"VADDSUBPS (AX),X1,X2", 16, true},
		{"VADDSUBPS (AX),Y1,Y2", 32, true},
		{"VADDSUBPD (AX),X1,X2", 16, true},
		{"VADDSUBPD (AX),Y1,Y2", 32, true},
		{"VROUNDPS $7,(AX),X2", 16, false},
		{"VROUNDPS $7,(AX),Y2", 32, false},
		{"VROUNDPD $7,(AX),X2", 16, false},
		{"VROUNDPD $7,(AX),Y2", 32, false},
		{"VROUNDSS $7,(AX),X1,X2", 4, true},
		{"VROUNDSD $7,(AX),X1,X2", 8, true},
	} {
		name := fmt.Sprint("DeadAlternatingRound", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-8\nMOVQ p+0(FP),AX\n", name)
		if row.second {
			source.WriteString("VPXOR Y1,Y1,Y1\n")
		}
		fmt.Fprintln(&source, row.instruction)
		source.WriteString("RET\n") // Rounded/arithmetic result and every alias are dead.
		fmt.Fprintf(&declarations, "func %s(p *byte)\n", name)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *);\n", name)
		fmt.Fprintf(&rows, "{%s,%d},\n", name, row.bytes)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	driver := `#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
` + prototypes.String() + `
typedef struct { void (*run)(uint8_t *); unsigned bytes; } Row;
static const Row rows[] = {` + rows.String() + `};
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page < 128) return 100;
    uint8_t *memory = mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if (memory == MAP_FAILED) return 101;
    memset(memory,0x5a,(size_t)page);
    if (mprotect(memory,(size_t)page,PROT_READ) || mprotect(memory+page,(size_t)page,PROT_NONE)) return 102;
    unsigned observations = 0, failures = 0;
    for (unsigned row=0;row<sizeof(rows)/sizeof(rows[0]);++row) {
        for (int kind=0;kind<3;++kind) {
            // NULL; precisely one complete original tuple; one byte short.
            // In particular scalar4/8 must not overread an X carrier.
            uint8_t *input = kind==0 ? (uint8_t *)0 : memory+page-rows[row].bytes+(kind==2);
            int trace[2];
            if (pipe(trace)) return 103;
            pid_t child = fork();
            if (child < 0) return 104;
            if (!child) {
                close(trace[0]);
                struct rlimit limit = {0,0};
                if (setrlimit(RLIMIT_CORE,&limit)) _exit(120);
                if (write(trace[1],"E",1)!=1) _exit(121);
                rows[row].run(input);
                // Do not read input here: a C probe must not supply the
                // missing NULL/partial-tuple fault on the kernel's behalf.
                for (unsigned byte=0;byte<16;++byte) if (memory[byte]!=0x5a) _exit(122);
                if (write(trace[1],"C",1)!=1) _exit(123);
                _exit(0);
            }
            close(trace[1]);
            int status=0;
            pid_t waited;
            do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
            if (waited!=child) return 105;
            char observed[3]={0,0,0};
            ssize_t count=read(trace[0],observed,sizeof(observed));
            close(trace[0]);
            int fault=WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS);
            int normal=WIFEXITED(status) && WEXITSTATUS(status)==0;
            int expectedFault=kind!=1;
            if (expectedFault ? !(fault && count==1 && observed[0]=='E') : !(normal && count==2 && observed[0]=='E' && observed[1]=='C')) {
                fprintf(stderr,"dead-fp row=%u bytes=%u kind=%d status=%x trace=%s count=%ld\n",row,rows[row].bytes,kind,status,observed,(long)count);
                ++failures;
            }
            ++observations;
        }
    }
    if (munmap(memory,(size_t)page*2)) return 106;
    printf("dead-fp kernels=10 observations=%u\n",observations);
    return observations==30 ? (failures ? 3 : 0) : 4;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("initialized dead-result source rejected before fault execution; not a semantic fault RED", err)
			}
			x86ConflictFunnelPortableRuntime(t, llc, clang, "dead-alternating-round", triple, ir, driver)
		})
	}
}
