//go:build unix

package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Called by the existing scalar dead-read cross-runtime owner. These SSE2
// memory operations have dead numerical results but observable exact-width
// reads. Neither an LLVM optimizer nor the C compiler may erase those reads.
func x86ScalarSqrtDeadReadFaultRuntime(t *testing.T) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, originals, pairs strings.Builder
	for _, row := range []struct {
		op     string
		width  int
		prefix byte
	}{{"SQRTSS", 4, 0xf3}, {"SQRTSD", 8, 0xf2}} {
		for _, forceNull := range []bool{false, true} {
			name := "Dead" + row.op
			zeroSource := ""
			originalAddress := "p"
			nativeZero := ""
			forced := 0
			if forceNull {
				name += "Null"
				zeroSource = "MOVL $0,AX\n"
				originalAddress = "NULL"
				nativeZero = "MOVL $0,DI\n"
				forced = 1
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVQ p+0(FP),AX\n%s%s (AX),X1\nMOVL $23063,ret+8(FP)\nRET\n", name, zeroSource, row.op)
			fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
			actual := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+nativeZero+row.op+" (DI),X1\nRET\n")
			memoryOpcode := []byte{row.prefix, 0x0f, 0x51, 0x0f, 0xc3}
			if !bytes.HasSuffix(actual, memoryOpcode) || !forceNull && !bytes.Equal(actual, memoryOpcode) ||
				forceNull && len(actual) <= len(memoryOpcode) {
				t.Fatal("original Go scalar memory SQRT/RET or forced address encoding changed", row.op, forceNull, actual)
			}
			fmt.Fprintf(&originals, "extern uint32_t %s(const uint8_t*);\n", name)
			fmt.Fprintf(&originals, "static uint32_t Original%s(const uint8_t *p) {\n", name)
			fmt.Fprintf(&originals, "    (void)p;\n    const uint8_t *address = %s;\n", originalAddress)
			fmt.Fprintf(&originals, "    __asm__ volatile(\"%s (%%0), %%%%xmm1\"::\"r\"(address):\"xmm1\",\"memory\");\n", strings.ToLower(row.op))
			originals.WriteString("    return UINT32_C(23063);\n}\n")
			fmt.Fprintf(&pairs, "{Original%s,%s,%d,%d},\n", name, name, row.width, forced)
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := fmt.Sprintf(x86ScalarSqrtDeadReadFaultC, originals.String(), pairs.String())
	if err := runtimeOracleFaultCorePolicy(main); err != nil {
		t.Fatal("SQRT fault children must retain the shared resource policy", err)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("missing complete scalar SQRT source translation", err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR-O2=%t", optimized), func(t *testing.T) {
					text := ir
					if optimized {
						text = x86MulDivRoundOptimize(t, ir)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							output := execution.compileAndRunLLVM(t, "scalar-sqrt-dead-read", text, main, level)
							if string(output) != "sqrt dead reads=4 memory outcomes=24 classifier tripwires=5 failures=0\n" {
								t.Fatal("original/transformed scalar reads or fault classification differ", string(output))
							}
						})
					}
				})
			}
		})
	}
}

const x86ScalarSqrtDeadReadFaultC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
` + numericalRuntimeFaultObservationC + `
%s
typedef uint32_t (*program)(const uint8_t*);
static const struct { program original, translated; unsigned width, force_null; } kernels[] = {
%s};

static void unexpected_signal(int signum) { _exit(signum == SIGILL ? 125 : 126); }

static int outcome(program fn, const uint8_t *p, uint8_t *fault_region, size_t fault_bytes) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        if (signal(SIGILL, unexpected_signal) == SIG_ERR ||
            signal(SIGALRM, unexpected_signal) == SIG_ERR) _exit(127);
        alarm(3);
        numerical_fault_begin(fault_region, fault_bytes);
        uint32_t marker = fn(p);
        _exit(marker == UINT32_C(23063) ? 0 : 124);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return -2;
    if (numerical_fault_status(status)) return 1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    if (WIFSIGNALED(status)) return -1000 - WTERMSIG(status);
    return -2000 - WEXITSTATUS(status);
}

static uint32_t missing_read(const uint8_t *p) { (void)p; return UINT32_C(23063); }
static uint32_t too_wide(const uint8_t *p) {
    __asm__ volatile("movdqu (%%0), %%%%xmm0"::"r"(p):"xmm0","memory");
    return UINT32_C(23063);
}
static uint32_t illegal(const uint8_t *p) { (void)p; __asm__ volatile("ud2"); return 0; }
static uint32_t timed_out(const uint8_t *p) { (void)p; raise(SIGALRM); return 0; }

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page < 128) return 1;
    size_t length = (size_t)page;
    uint8_t *memory = mmap(NULL, 2*length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) return 2;
    if (mprotect(memory+length, length, PROT_NONE)) { munmap(memory, 2*length); return 3; }
    uint8_t *guard = memory + length;
    int failed = 0;
    unsigned observations = 0;
    // These tripwires reject a missing read, an over-wide read, an illegal
    // instruction and an alarm. Only synchronous faults in the bound region
    // become memory outcomes; SIGILL and deadlines cannot impersonate them.
    if (outcome(missing_read, NULL, NULL, length) != 0 ||
        outcome(missing_read, guard-3, guard, length) != 0 ||
        outcome(too_wide, guard-5, guard, length) != 1 ||
        outcome(illegal, NULL, NULL, length) >= 0 ||
        outcome(timed_out, NULL, NULL, length) >= 0) failed = 1;
    for (unsigned kernel = 0; kernel < 4; ++kernel) {
        unsigned width = kernels[kernel].width;
        uint64_t one = width == 4 ? UINT64_C(0x3f800000) : UINT64_C(0x3ff0000000000000);
        uint8_t *valid = guard-width-1;
        memcpy(valid, &one, width);
        for (unsigned address = 0; address < 3; ++address) {
            const uint8_t *p = address == 0 ? NULL : address == 1 ? guard-width+1 : valid;
            const uint8_t *effective = kernels[kernel].force_null ? NULL : p;
            uint8_t *fault = effective == NULL ? NULL : guard;
            int expected = kernels[kernel].force_null || address != 2;
            int original = outcome(kernels[kernel].original, p, fault, length);
            int translated = outcome(kernels[kernel].translated, p, fault, length);
            observations += 2;
            if (original != expected || translated != expected) {
                fprintf(stderr, "sqrt kernel=%%u width=%%u forced-null=%%u address=%%u original=%%d translated=%%d want=%%d\n",
                    kernel, width, kernels[kernel].force_null, address, original, translated, expected);
                failed = 1;
            }
        }
    }
    if (munmap(memory, 2*length)) failed = 1;
    if (failed || observations != 24) return 4;
    puts("sqrt dead reads=4 memory outcomes=24 classifier tripwires=5 failures=0");
    return 0;
}
`
