//go:build unix

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func x86UndefinedTrapRequireOriginalSignal(t *testing.T, output []byte, err error) {
	t.Helper()
	if !x86UndefinedTrapOriginalSignal(output, err) {
		t.Fatalf("unchanged Go object did not raise the actual undefined-instruction fault: %v\n%s", err, output)
	}
}

func x86UndefinedTrapOriginalSignal(output []byte, err error) bool {
	// Like the Go-assembler oracle, accept only a directly completed process
	// outcome. errors.As would hide cleanup, pipe or context failures joined
	// to the otherwise expected exit status.
	exit, completed := err.(*exec.ExitError)
	return completed && exit.ProcessState != nil && exit.ProcessState.Exited() &&
		exit.ExitCode() == 2 && strings.Contains(string(output), "SIGILL: illegal instruction") &&
		strings.Contains(string(output), "main.fault")
}

func TestX86UndefinedTrapExitStatusFixture(t *testing.T) {
	if os.Getenv("PLAN9ASM_UNDEFINED_EXIT_FIXTURE") == "1" {
		os.Exit(2)
	}
}

func TestX86UndefinedTrapExpectedFaultRejectsUnknownLifecycle(t *testing.T) {
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestX86UndefinedTrapExitStatusFixture$")
	command.Env = append(os.Environ(), "PLAN9ASM_UNDEFINED_EXIT_FIXTURE=1")
	_, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	// This parser control obtains a real exit status, but its diagnostic is
	// deliberately synthetic. It is not an original-Go signal observation.
	output := []byte("SIGILL: illegal instruction\nmain.fault\n")
	if !x86UndefinedTrapOriginalSignal(output, err) {
		t.Fatalf("actual completed exit-2 parser control failed: %v", err)
	}
	for _, test := range []struct {
		name   string
		err    error
		output []byte
	}{
		{"cleanup", errors.Join(err, errors.New("unknown descendant cleanup")), output},
		{"deadline", errors.Join(err, context.DeadlineExceeded), output},
		{"cancellation", errors.Join(err, context.Canceled), output},
		{"wrapped outcome", fmt.Errorf("unknown wrapper: %w", err), output},
		{"uncompleted exit", &exec.ExitError{}, output},
		{"wrong signal", err, []byte("SIGTRAP: trace trap\nmain.fault\n")},
		{"wrong function", err, []byte("SIGILL: illegal instruction\nmain.other\n")},
		{"unknown exit", errors.New("unbound process failure"), output},
	} {
		t.Run(test.name, func(t *testing.T) {
			if x86UndefinedTrapOriginalSignal(test.output, test.err) {
				t.Fatal("expected-fault parser erased an unknown lifecycle or diagnostic")
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86UndefinedTrapOriginalAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			goos := runtime.GOOS
			if strings.Contains(execution.triple, "linux") {
				goos = "linux"
			}
			original := x86UndefinedTrapBuildOriginal(t, goos, "amd64", raw)
			arguments := execution.command(original)
			ctx, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
			// The Go runtime reports SIGILL and exits 2. It must not escalate
			// the oracle into a core-producing crash because of inherited env.
			command.Env = append(os.Environ(), "GOTRACEBACK=system")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			cancel()
			x86UndefinedTrapRequireOriginalSignal(t, output, err)
			ir := x86UndefinedTrapIR(t, x86UndefinedTrapFixture(raw), "amd64", execution.triple, "Go")
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					optimized := ir
					if level == "-O2" {
						optimized = x86UndefinedTrapOptimizedIR(t, ir)
					}
					output := execution.compileAndRunLLVM(t, "undefined", optimized, x86UndefinedTrapIndependentC, level)
					if string(output) != "undefined-instruction SIGILL verified\n" {
						t.Fatalf("independent real-signal oracle: %q", output)
					}
				})
			}
		})
	}
}

// A child returning normally, an int3/SIGTRAP, and a generic abort all fail.
// The parent observes the kernel's signal, independently of translator IR.
const x86UndefinedTrapIndependentC = `
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern void fault(void);

int main(void) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        fault();
        _exit(91);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 2;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGILL) {
        fprintf(stderr, "expected SIGILL, got child status=%x\n", status);
        return 3;
    }
    puts("undefined-instruction SIGILL verified");
    return 0;
}
`
