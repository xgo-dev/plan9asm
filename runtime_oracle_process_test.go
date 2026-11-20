package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

// Compile process setup as its own translation unit. Its system headers must
// not precede an oracle's feature macros or change the oracle's C namespace.
func runtimeOracleProcessSource(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "oracle_process.c")
	if err := os.WriteFile(path, []byte(runtimeOracleProcessSetupC), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCrossLinuxRuntimeMatrixOracleProcessHeaderIsolation(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	// The fixture owns its feature-test macros and C identifiers. Shared
	// process setup must neither pre-include headers nor occupy this scope.
	const main = `#define _GNU_SOURCE
#include <stdint.h>
#if defined(__linux__)
#include <sched.h>
#include <sys/prctl.h>
#endif
static int read(void) { return 7; }
int main(void) {
#if defined(__linux__)
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return 1;
    if (CPU_COUNT(&allowed) == 0) return 2;
    if (prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) return 3;
#endif
    return read() == 7 ? 0 : 4;
}
`
	const ir = "define i32 @unused() { ret i32 0 }\n"
	t.Run("shared runtime", func(t *testing.T) {
		compileAndRunRuntimeTestWithCompiler(t, execution.llc, execution.compiler,
			"header_isolation", execution.triple, ir, main, execution.prefix)
	})
	t.Run("comparison runtime", func(t *testing.T) {
		execution.compileAndRunLLVM(t, "header_isolation", ir, main, "-O2")
	})
}

// Linux ignores RLIMIT_CORE when core_pattern names a pipe collector. Every
// standalone C oracle opts out before main so its fault children inherit the
// setting, without changing the Go test process or the machine-wide policy.
// Keep each child's checked zero rlimit as well for the other Unix platforms.
// See https://man7.org/linux/man-pages/man5/core.5.html.
const runtimeOracleProcessSetupC = `
#if defined(_WIN32)
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <process.h>
__attribute__((constructor)) static void plan9asm_oracle_process_setup(void) {
    if (_setmode(_fileno(stdout), _O_BINARY) == -1 ||
        _setmode(_fileno(stderr), _O_BINARY) == -1) _exit(125);
}
#elif defined(__linux__)
#include <sys/prctl.h>
#include <unistd.h>
__attribute__((constructor)) static void plan9asm_oracle_process_setup(void) {
    if (prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) _exit(125);
}
#endif
`
