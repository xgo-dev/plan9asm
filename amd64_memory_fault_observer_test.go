package plan9asm

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Each probe is an owned, directly launched process. Do not catch native
// exceptions in C or accept setup exits as evidence of a memory fault.
func x86ObserveMemoryFault(t *testing.T, execution x86FloatCompareExecution, executable string, row, probe, original int) string {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	child, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	args := execution.command(executable, strconv.Itoa(row), strconv.Itoa(probe), strconv.Itoa(original))
	stdout, stderr, err := runtimeOracleMachineOutput(child, exec.CommandContext(child, args[0], args[1:]...))
	if child.Err() != nil {
		t.Fatal(child.Err())
	}
	witness := fmt.Sprintf("memory enter %d %d %d\n", row, probe, original)
	result, cause := x86NativeFaultResult(runtime.GOOS, string(stdout), witness, "memory complete\n", err)
	if cause != nil {
		t.Fatalf("row=%d probe=%d original=%d: %v\nstdout: %q\nstderr: %q", row, probe, original, cause, stdout, stderr)
	}
	return result
}

func x86CheckMemoryFaultMatrix(t *testing.T, execution x86FloatCompareExecution, executable string, rows int) {
	t.Helper()
	required := make([]bool, rows)
	for row := range required {
		required[row] = true
	}
	x86CheckMemoryAccessMatrix(t, execution, executable, required)
}

func x86CheckMemoryAccessMatrix(t *testing.T, execution x86FloatCompareExecution, executable string, required []bool) {
	t.Helper()
	for row, reads := range required {
		for probe := 0; probe < 3; probe++ {
			// A volatile byte read supplies an independent access-extent
			// reference, not evidence of original AVX/EVEX execution.
			want := x86ObserveMemoryFault(t, execution, executable, row, probe, 1)
			if probe == 2 || !reads {
				if want != "return" {
					t.Fatalf("row %d probe %d: accessible or suppressed source faulted: %s", row, probe, want)
				}
			} else if want != "segv" && want != "bus" {
				t.Fatalf("row %d probe %d: native access did not fault: %s", row, probe, want)
			}
			if got := x86ObserveMemoryFault(t, execution, executable, row, probe, 0); got != want {
				t.Fatalf("row %d probe %d: translated %s, native access %s", row, probe, got, want)
			}
		}
	}
	t.Logf("%d rows: NULL, partial-page and complete-page inputs; independent native access and translated outcomes agree", len(required))
}

func x86MemoryFaultDriver(declarations, rows string) string {
	return x86MemoryFaultSupportC + declarations +
		"static const struct memory_case cases[] = {\n" + rows + "};\n" + x86MemoryFaultMainC
}

func TestX86MemoryFaultObserverRejectsSetupAndCanaryFailures(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const callbacks = `
static int canary_failure(const uint8_t *p) { (void)p; return 91; }
static int fake_signal_exit(const uint8_t *p) { (void)p; return 139; }
`
	driver := x86MemoryFaultDriver(callbacks, "{canary_failure, 4, 3}, {fake_signal_exit, 4, 3},")
	executable := execution.compileLLVM(t, "memory-fault-controls", "", driver, "-O2")
	for _, row := range []int{0, 1, 99} {
		ctx, cancel := runtimeOracleStageContext(t)
		args := execution.command(executable, strconv.Itoa(row), "2", "0")
		stdout, _, err := runtimeOracleMachineOutput(ctx, exec.CommandContext(ctx, args[0], args[1:]...))
		cancel()
		witness := fmt.Sprintf("memory enter %d 2 0\n", row)
		if result, cause := x86NativeFaultResult(runtime.GOOS, string(stdout), witness, "memory complete\n", err); cause == nil {
			t.Fatalf("setup/canary error became memory evidence: row=%d result=%s", row, result)
		}
	}
}

const x86MemoryFaultSupportC = `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
` + x86TestGuardPagesC + `
struct memory_case {
    int (*run)(const uint8_t *);
    unsigned bytes;
    unsigned accessible;
};

static int memory_fault_setup(unsigned leading) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#else
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 120;
#endif
    if (setup_guard_before(leading) || page < 64) return 81;
    for (size_t i = 0; i < page; ++i) guard[i] = (uint8_t)(i * 13 + 17);
    return 0;
}
`

const x86MemoryFaultMainC = `
int main(int argc, char **argv) {
    if (argc != 4) return 80;
    unsigned row, probe, original;
    char tail;
    if (sscanf(argv[1], "%u%c", &row, &tail) != 1 ||
            sscanf(argv[2], "%u%c", &probe, &tail) != 1 ||
            sscanf(argv[3], "%u%c", &original, &tail) != 1 ||
            row >= sizeof(cases) / sizeof(cases[0]) || probe > 2 || original > 1) return 80;
    int setup = memory_fault_setup(0);
    if (setup) return setup;
    struct memory_case kernel = cases[row];
    if (kernel.bytes > page || (kernel.bytes ? kernel.accessible >= kernel.bytes : kernel.accessible != 0)) return 82;
    const uint8_t *input = probe == 0 ? NULL :
        guard + page - (probe == 1 ? kernel.accessible : kernel.bytes);

    printf("memory enter %u %u %u\n", row, probe, original);
    if (fflush(stdout)) return 83;
    if (original) {
        const volatile uint8_t *source = input;
        volatile uint8_t sink = 0;
        for (unsigned i = 0; i < kernel.bytes; ++i) sink ^= source[i];
    } else {
        int result = kernel.run(input);
        if (result) return result;
    }
    if (free_guard()) return 84;
    puts("memory complete");
    return fflush(stdout) ? 85 : 0;
}
`
