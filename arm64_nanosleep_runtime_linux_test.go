//go:build go1.27 && (amd64 || arm64)

package plan9asm

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64NanosleepPrivateInput(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	if triple != "aarch64-unknown-linux-gnu" {
		t.Fatal("nanosleep requires the actual Linux/ARM64 kernel counterpart")
	}
	directory, packagePath, _ := arm64NanosleepRuntimeFixture(t)
	arm64NanosleepRuntimeOriginalObjects(t, directory, packagePath)
	request := arm64ByteCarrierRequest(t, directory, packagePath)
	arguments := []string{"test", "-p=1", "-mod=readonly", "-run=^TestOriginalNanosleepInput$", "-count=1", "-v"}
	if len(runner) != 0 {
		quoted, err := arm64PaddingGoExecArguments(runner)
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "-exec="+quoted)
	}
	ctx, release := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, request.GoBinary, append(arguments, ".")...)
	command.Dir, command.Env = directory, request.Environment
	output, err := runtimeOracleCombinedOutput(ctx, command)
	release()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestOriginalNanosleepInput") {
		t.Fatalf("ORIGINAL_NANOSLEEP_KERNEL_PRECONDITION: %v\n%s", err, output)
	}
	for _, axis := range []string{"usec=0", "usec=1", "usec=2000", "interrupted-null-rem"} {
		if strings.Count(string(output), "ORIGINAL_NANOSLEEP_KERNEL_PASS "+axis+"\n") != 1 {
			t.Fatalf("missing/ambiguous actual original kernel axis %q\n%s", axis, output)
		}
	}
	t.Logf("ORIGINAL_NANOSLEEP_KERNEL_OUTPUT_BEGIN\n%sORIGINAL_NANOSLEEP_KERNEL_OUTPUT_END", output)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := arm64NanosleepInputAPI(t, api, triple, arm64NanosleepInputSource)
			if err != nil {
				t.Fatal("actual original kernel P did not grant the source consumer", err)
			}
			for _, optimization := range []int{0, 2} {
				t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "nanosleep_input", triple,
						ir, arm64NanosleepRuntimeDriver, runner, optimization)
					t.Logf("LLVM_NANOSLEEP_KERNEL_PASS %s O%d values=5x2 kernel=3 interrupted-null-rem=1", api, optimization)
				})
			}
		})
	}
}

// Interception checks the actual translated arguments against an independent
// uint32 equation, including both field widths and NULL rem. It then invokes
// the real A64 SVC for short sleeps and EINTR, checks the input bytes are
// unchanged, and maps the raw kernel return to libc's errno contract. The source
// has a void return: neither this driver nor its proof authorizes observing R0
// or native NZCV in the translated assembly.
const arm64NanosleepRuntimeDriver = `#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern void translated_sleep(uint32_t) __asm__("\"example.invalid/sleepinput.sleep\"");
struct request { int64_t seconds, nanoseconds; };
_Static_assert(sizeof(struct request)==16,"actual A64 kernel timespec width");
static uint32_t expected;
static int mode, forced_error, calls;
static int start_fd=-1;
static volatile sig_atomic_t interrupted;

static void interrupt_handler(int signo) { if(signo==SIGUSR1) interrupted=1; }

static long original_kernel(const struct request *request) {
    register long number __asm__("x8")=101;
    register long input __asm__("x0")=(long)request;
    register long rem __asm__("x1")=0;
    __asm__ volatile("svc #0" : "+r"(input), "+r"(rem), "+r"(number) : : "memory", "cc");
    return input;
}

long syscall(long number,...) {
    va_list arguments;
    va_start(arguments,number);
    const struct request *request=(const struct request *)va_arg(arguments,long);
    long rem=va_arg(arguments,long);
    long unused[4];
    for(unsigned i=0;i<4;i++) unused[i]=va_arg(arguments,long);
    va_end(arguments);
    if(number!=101 || !request || rem || unused[0] || unused[1] || unused[2] || unused[3]) abort();
    struct request before;
    memcpy(&before,request,sizeof(before));
    uint64_t seconds=(uint64_t)expected/UINT64_C(1000000);
    uint64_t nanoseconds=((uint64_t)expected-seconds*UINT64_C(1000000))*UINT64_C(1000);
    if(before.seconds!=(int64_t)seconds || before.nanoseconds!=(int64_t)nanoseconds) abort();
    calls++;
    if(!mode) {
        errno=EINTR;
        return forced_error ? -1 : 0;
    }
    if(mode==2) {
        const char ready='R';
        if(start_fd<0 || write(start_fd,&ready,1)!=1) abort();
    }
    long raw=original_kernel(request);
    if(memcmp(&before,request,sizeof(before))) abort();
    if((mode==1 && raw!=0) || (mode==2 && (raw!=-EINTR || !interrupted))) abort();
    if(raw<0 && raw>=-4095) { errno=(int)-raw; return -1; }
    return raw;
}

int cliteErrno(void) { return errno; }

int main(void) {
    const uint32_t values[]={0,1,999999,1000000,UINT32_MAX};
    for(unsigned error=0;error<2;error++) {
        forced_error=(int)error;
        for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
            expected=values[i];
            translated_sleep(expected);
        }
    }
    mode=1;
    const uint32_t short_values[]={0,1,2000};
    for(unsigned i=0;i<sizeof(short_values)/sizeof(short_values[0]);i++) {
        expected=short_values[i];
        translated_sleep(expected);
    }
    struct sigaction action;
    memset(&action,0,sizeof(action));
    action.sa_handler=interrupt_handler;
    if(sigemptyset(&action.sa_mask) || sigaction(SIGUSR1,&action,0)) return 1;
    int ready[2], done[2];
    if(pipe(ready) || pipe(done)) return 2;
    pid_t parent=getpid();
    if(gettid()!=parent) return 3;
    pid_t child=fork();
    if(child<0) return 2;
    if(child==0) {
        close(ready[1]);
        close(done[1]);
        char token;
        if(read(ready[0],&token,1)!=1 || token!='R') _exit(1);
        struct pollfd complete={.fd=done[0],.events=POLLIN};
        for(unsigned attempt=0;attempt<250;attempt++) {
            // A parent that failed/aborted is no longer this signal owner.
            if(getppid()!=parent || tgkill(parent,parent,SIGUSR1)) _exit(2);
            int result=poll(&complete,1,2);
            if(result<0) _exit(3);
            if(result>0) {
                if(complete.revents!=POLLIN || read(done[0],&token,1)!=1 || token!='D') _exit(4);
                close(ready[0]);
                close(done[0]);
                _exit(0);
            }
        }
        _exit(5);
    }
    close(ready[0]);
    close(done[0]);
    start_fd=ready[1];
    mode=2;
    expected=1000000;
    translated_sleep(expected);
    const char complete='D';
    if(write(done[1],&complete,1)!=1) return 4;
    int status;
    pid_t joined;
    do {
        joined=waitpid(child,&status,0);
    } while(joined<0 && errno==EINTR);
    if(joined!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=0) return 5;
    close(ready[1]);
    close(done[1]);
    if(calls!=14 || !interrupted) return 4;
    puts("ACTUAL_NANOSLEEP_INPUT_KERNEL_COMPLETE values=10 kernel=3 EINTR=1 NULLrem=1");
    return 0;
}
`
