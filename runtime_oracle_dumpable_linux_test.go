package plan9asm

import (
	"runtime"
	"testing"
)

func TestCrossLinuxRuntimeMatrixOracleDisablesCorePipeCollection(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc and clang are required")
	}
	const ir = "define i32 @oracle_value() { ret i32 17 }\n"
	const source = `
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
extern int oracle_value(void);
int main(void) {
    if (prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) _exit(3);
        _exit(oracle_value() == 17 ? 0 : 4);
    }
    int status;
    if (waitpid(child, &status, 0) != child) return 5;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 6;
}
`
	t.Run("generic", func(t *testing.T) {
		compileAndRunRuntimeTest(t, llc, clang, "dumpable", ir, source)
	})
	t.Run("comparison", func(t *testing.T) {
		execution := x86FloatCompareExecution{
			llc: llc, triple: testTargetTriple(runtime.GOOS, runtime.GOARCH),
			compiler: []string{clang},
		}
		execution.compileAndRunLLVM(t, "dumpable", ir, source, "-O2")
	})
}
