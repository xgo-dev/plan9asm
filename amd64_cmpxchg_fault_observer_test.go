package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func x86CMPXCHGObserveFault(t *testing.T, execution x86FloatCompareExecution, executable string, index, address, original int) (string, error) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	return x86CMPXCHGObserveFaultContext(ctx, execution, executable, index, address, original)
}

func x86CMPXCHGObserveFaultContext(ctx context.Context, execution x86FloatCompareExecution, executable string, index, address, original int) (string, error) {
	// Each leaf executable is the owned child: no fork, descendant, exception
	// handler or native unwinder can hide the actual instruction's termination.
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := execution.command(executable, strconv.Itoa(index), strconv.Itoa(address), strconv.Itoa(original))
	stdout, stderr, err := runtimeOracleMachineOutput(child, exec.CommandContext(child, args[0], args[1:]...))
	if child.Err() != nil {
		return "", child.Err()
	}
	witness := fmt.Sprintf("CMPXCHG enter %d %d %d\n", index, address, original)
	result, cause := x86CMPXCHGFaultResult(runtime.GOOS, string(stdout), witness, err)
	if cause != nil {
		return "", fmt.Errorf("kernel %d address %d original %d: %w\nstdout: %q\nstderr: %q", index, address, original, cause, stdout, stderr)
	}
	return result, nil
}

func x86CMPXCHGFaultResult(goos, stdout, witness string, err error) (string, error) {
	result, cause := x86NativeFaultResult(goos, stdout, witness, "CMPXCHG complete\n", err)
	if cause == nil && result == "fpe" {
		return "", fmt.Errorf("floating-point fault is not a CMPXCHG outcome")
	}
	return result, cause
}

func x86NativeFaultResult(goos, stdout, witness, completed string, err error) (string, error) {
	if err == nil {
		if stdout == witness+completed {
			return "return", nil
		}
		return "", fmt.Errorf("missing exact completed state/canary receipt")
	}
	// Do not unwrap joined errors: cancellation, pipes and ownership cleanup
	// failures must not become accepted native exceptions.
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ProcessState == nil || stdout != witness {
		return "", fmt.Errorf("not an isolated native fault after the exact entry receipt: %w", err)
	}
	status, ok := exit.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return "", fmt.Errorf("missing actual process termination status")
	}
	if goos == "windows" {
		return x86NativeWindowsFault(uint32(exit.ExitCode()))
	}
	if status.Signaled() {
		switch status.Signal() {
		case syscall.SIGSEGV:
			return "segv", nil
		case syscall.SIGBUS:
			return "bus", nil
		case syscall.SIGILL:
			return "ill", nil
		case syscall.SIGFPE:
			return "fpe", nil
		}
	}
	return "", fmt.Errorf("setup, state or unexpected process failure: %w", err)
}

func x86NativeWindowsFault(code uint32) (string, error) {
	if code == 0xc000008f { // EXCEPTION_FLT_INEXACT_RESULT, not other FP exceptions.
		return "fpe", nil
	}
	return x86CMPXCHGWindowsFault(code)
}

func TestX86NativeWindowsPrecisionFaultCode(t *testing.T) {
	if got, err := x86NativeWindowsFault(0xc000008f); err != nil || got != "fpe" {
		t.Fatalf("native precision exception: %s, %v", got, err)
	}
	for _, code := range []uint32{136, 0xc000008e, 0xc0000090, 0xc0000091, 0xc0000094} {
		if _, err := x86NativeWindowsFault(code); err == nil {
			t.Fatalf("different exception/ordinary exit became precision evidence: %#x", code)
		}
	}
	if _, err := x86CMPXCHGWindowsFault(0xc000008f); err == nil {
		t.Fatal("precision exception became a registered CMPXCHG fault")
	}
}

func x86CMPXCHGWindowsFault(code uint32) (string, error) {
	// GetExitCodeProcess returns the unhandled exception value, not 128+signal.
	// Keep only these three native exception classes; ordinary exits never
	// count as faults, even when original and translated setup fail identically.
	switch code {
	case 0xc0000005: // EXCEPTION_ACCESS_VIOLATION
		return "segv", nil
	case 0x80000002: // EXCEPTION_DATATYPE_MISALIGNMENT
		return "bus", nil
	case 0xc000001d: // EXCEPTION_ILLEGAL_INSTRUCTION
		return "ill", nil
	}
	return "", fmt.Errorf("not a registered native Windows exception: %#x", code)
}

func TestX86CMPXCHGWindowsFaultCodes(t *testing.T) {
	for code, want := range map[uint32]string{0xc0000005: "segv", 0x80000002: "bus", 0xc000001d: "ill"} {
		if got, err := x86CMPXCHGWindowsFault(code); err != nil || got != want {
			t.Fatalf("exception %#x: %s, %v", code, got, err)
		}
	}
	for _, code := range []uint32{0, 1, 80, 82, 83, 84, 85, 86, 87, 88, 120, 125, 132, 135, 137, 139, 259, 0xc00000fd, 0xffffffff} {
		if _, err := x86CMPXCHGWindowsFault(code); err == nil {
			t.Fatalf("ordinary/setup/stack-overflow exit %#x became native opcode evidence", code)
		}
	}
}

func TestX86CMPXCHGFaultObserverRejectsFalseEvidence(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const driver = `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/resource.h>
#endif
int main(int argc, char **argv) {
#ifdef _WIN32
 SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
 struct rlimit no_core = {0, 0};
 if (setrlimit(RLIMIT_CORE, &no_core)) return 120;
#endif
 if (argc != 4) return 80;
 int mode = atoi(argv[1]);
 if (mode == 2) return 82;
 printf("CMPXCHG enter %d 0 0\n", mode == 7 ? 99 : mode);
 if (fflush(stdout)) return 87;
 if (mode == 1 || mode == 7) __asm__ volatile("movl $0,(%0)" :: "r"((uintptr_t)0) : "memory");
 if (mode == 3) return 139;
 if (mode == 4) return 0;
 if (mode == 5) __asm__ volatile("ud2");
 if (mode == 6) return 85;
 if (mode == 8) for (;;) __asm__ volatile("" ::: "memory");
 puts("CMPXCHG complete");
 return 0;
}
`
	executable := execution.compileLLVM(t, "fault-controls", "", driver, "-O0")
	for _, test := range []struct {
		mode int
		want string
	}{{0, "return"}, {1, "segv"}, {2, ""}, {3, ""}, {4, ""}, {5, "ill"}, {6, ""}, {7, ""}} {
		t.Run(strconv.Itoa(test.mode), func(t *testing.T) {
			got, err := x86CMPXCHGObserveFault(t, execution, executable, test.mode, 0, 0)
			if got != test.want || (err == nil) != (test.want != "") {
				t.Fatalf("got %s, %v; want %s", got, err, test.want)
			}
		})
	}
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if _, err := x86CMPXCHGObserveFaultContext(ctx, execution, executable, 8, 0, 0); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cancellation became a native opcode outcome: %v", err)
		}
	})
	t.Run("joined-cleanup", func(t *testing.T) {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		args := execution.command(executable, "5", "0", "0")
		stdout, _, err := runtimeOracleMachineOutput(ctx, exec.CommandContext(ctx, args[0], args[1:]...))
		const witness = "CMPXCHG enter 5 0 0\n"
		if got, cause := x86CMPXCHGFaultResult(runtime.GOOS, string(stdout), witness, err); cause != nil || got != "ill" {
			t.Fatal("missing actual illegal-instruction control", got, cause)
		}
		if _, cause := x86CMPXCHGFaultResult(runtime.GOOS, string(stdout), witness, errors.Join(err, fmt.Errorf("owned cleanup failure"))); cause == nil {
			t.Fatal("cleanup error was erased by the native exception")
		}
	})
}
