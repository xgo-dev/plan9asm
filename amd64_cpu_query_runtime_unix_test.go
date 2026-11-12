//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86CPUQueryOriginalAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	referenceSource, referenceExecutable := filepath.Join(dir, "reference.c"), filepath.Join(dir, "reference")
	if err := os.WriteFile(referenceSource, []byte("#define REFERENCE_ONLY 1\n"+x86CPUQueryIndependentC), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, referenceSource, referenceExecutable)
	reference := string(execution.run(t, referenceExecutable))
	lines := strings.Split(strings.TrimSpace(reference), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "cpu query ") || !strings.HasPrefix(lines[1], "xgetbv ") {
		t.Fatalf("independent native CPU/OS-state reference: %q", reference)
	}
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			declarations, assembly := x86CPUQueryRuntimeFixtures(raw, "amd64")
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			original := x86CPUQueryBuildOriginal(t, execution, declarations, assembly)
			for _, suffix := range []string{"", "_af"} {
				arguments := execution.command(original)
				arguments = append(arguments, suffix)
				ctx, cancel := runtimeOracleStageContext(t)
				command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
				command.Env = append(os.Environ(), "GOTRACEBACK=system")
				output, err := runtimeOracleCombinedOutput(ctx, command)
				cancel()
				if lines[1] == "xgetbv SIGILL" {
					if !x86UndefinedTrapOriginalSignal(output, err) || !strings.HasPrefix(string(output), lines[0]+"\n") {
						t.Fatalf("unchanged Go XGETBV did not retain its actual unavailable-ISA fault: %v\n%s", err, output)
					}
				} else if err != nil || string(output) != reference {
					t.Fatalf("original Go query values/zero extension/flags/canaries differ from native reference: %v\n%s\nreference=%s", err, output, reference)
				}
			}
			ir := x86NarrowOracleIR(t, assembly, "package cpuquery\n"+declarations, execution.triple)
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					input := ir
					if level == "-O2" {
						input = x86UndefinedTrapOptimizedIR(t, input)
					}
					output := execution.compileAndRunLLVM(t, "cpuquery", input, x86CPUQueryIndependentC, level)
					if string(output) != reference {
						t.Fatalf("LLVM query result/fault differs from independent native reference: %q / %q", output, reference)
					}
				})
			}
		})
	}
}

func x86CPUQueryBuildOriginal(t *testing.T, execution x86FloatCompareExecution, declarations, assembly string) string {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module cpuquery\n\ngo 1.20\n", "main.go": x86CPUQueryOriginalDriver,
		"decl.go": "package main\n" + declarations, "query_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, "original-go")
	command := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=1", "-o", executable, ".")
	command.Dir = dir
	goos := runtime.GOOS
	if strings.Contains(execution.triple, "linux") {
		goos = "linux"
	}
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH=amd64", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=")
	x86FloatCompareCaptureCommand(t, command)
	return executable
}

const x86CPUQueryIndependentC = `
#include <cpuid.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

// Observe the actual instruction, not an advertised CPUID capability. An
// emulator may mask OSXSAVE while still implementing XGETBV successfully.
static int native_state(unsigned *low, unsigned *high) {
    int channel[2];
    if (pipe(channel)) return -1;
    pid_t child=fork();
    if (child<0) {
        close(channel[0]);
        close(channel[1]);
        return -1;
    }
    if (child==0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        if (close(channel[0])) _exit(121);
        unsigned values[2];
        __asm__ volatile("xgetbv" : "=a"(values[0]),"=d"(values[1]) : "c"(0));
        if (write(channel[1],values,sizeof(values))!=sizeof(values) || close(channel[1])) _exit(122);
        _exit(0);
    }
    if (close(channel[1])) return -1;
    int status=0;
    pid_t waited;
    do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
    unsigned values[2]={0,0};
    ssize_t count=read(channel[0],values,sizeof(values));
    if (close(channel[0]) || waited!=child) return -1;
    if (WIFSIGNALED(status) && WTERMSIG(status)==SIGILL && count==0) return 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status)!=0 || count!=sizeof(values)) return -1;
    *low=values[0];
    *high=values[1];
    return 1;
}

#if !REFERENCE_ONLY
extern void query(uint64_t *);
extern void query_af(uint64_t *);
extern void fault(uint64_t *);
extern void fault_af(uint64_t *);

static int check(uint64_t *out, uint64_t flags, unsigned csr) {
    return (out[4]&0x8d5)==flags && out[5]==csr &&
        out[6]==UINT64_C(0xabcdef0123456789) && out[7]==UINT64_C(0x13579bdf2468ace0);
}
#endif

int main(void) {
    unsigned a,b,c,d,low=0,high=0;
    int available=native_state(&low,&high);
    if (available<0) return 10;
    if (!__get_cpuid(0,&a,&b,&c,&d)) return 11;
#if !REFERENCE_ONLY
    void (*cpu[])(uint64_t *)={query,query_af};
    void (*state[])(uint64_t *)={fault,fault_af};
    const uint64_t flags[]={0x8c5,0x10};
    for (unsigned index=0;index<2;index++) {
        uint64_t out[8]={0,0,0,0,0,0,UINT64_C(0xabcdef0123456789),UINT64_C(0x13579bdf2468ace0)};
        unsigned before,after;
        __asm__ volatile("stmxcsr %0" : "=m"(before));
        cpu[index](out);
        __asm__ volatile("stmxcsr %0" : "=m"(after));
        if (!check(out,flags[index],before) || after!=before || out[0]!=a || out[1]!=b || out[2]!=c || out[3]!=d) return 12;
        if (available) {
            state[index](out);
            __asm__ volatile("stmxcsr %0" : "=m"(after));
            if (!check(out,flags[index],before) || after!=before || out[0]!=low || out[3]!=high ||
                out[1]!=UINT64_C(0x7e6d5c4b3a291807) || out[2]!=UINT64_C(0xa1b2c3d400000000)) return 13;
        } else {
            pid_t child=fork();
            if (child<0) return 14;
            if (child==0) {
                struct rlimit no_core = {0, 0};
                if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
                state[index](out);
                _exit(91);
            }
            int status=0;
            if (waitpid(child,&status,0)!=child || !WIFSIGNALED(status) || WTERMSIG(status)!=SIGILL) return 15;
        }
    }
#endif
    printf("cpu query %x %x %x %x\n",a,b,c,d);
    if (available) printf("xgetbv %x %x\n",low,high);
    else puts("xgetbv SIGILL");
    return 0;
}
`
