//go:build darwin || linux

package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoModuleFunctionValueCodeWord(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	// A caller-selected, version-checked C compiler may carry an explicitly
	// observed SDK selection. Otherwise retain the shared native SDK reader.
	if compiler := os.Getenv("CC"); compiler != "" {
		version, err := llvm22ToolOutput(compiler, "--version")
		if err != nil || !llvm22ToolVersionRE.Match(version) {
			t.Fatal("configured portable C compiler must be LLVM22", err)
		}
		execution.compiler = []string{compiler, "-target", execution.triple}
	}
	arch, move := "amd64", "MOVQ"
	if strconv.IntSize == 32 {
		arch, move = "386", "MOVL"
	}
	assembly := string(goFuncvalGlobalSource(arch, move+" ·callback(SB),DI\n"+move+" (DI),AX"))
	dead := string(goFuncvalGlobalSource(arch, move+" ·callback(SB),DI\n"+move+" (DI),AX\n"+move+" $7,AX"))
	assembly += strings.ReplaceAll(dead, "view", "dead")
	declarations := goFuncvalGlobalDeclarations("var callback func(uintptr) uintptr") + "func dead() uintptr\n"
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	driver := fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
extern uintptr_t view(void) __asm__("%[1]sordinaryglobals.view");
extern uintptr_t dead(void) __asm__("%[1]sordinaryglobals.dead");
uintptr_t *callback __asm__("%[1]sordinaryglobals.callback");
static void target0(void) {}
static void target1(void) {}
static void target2(void) {}
static int null_fault(uintptr_t (*run)(void)) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
        alarm(5);
        callback = 0;
        (void)run();
        _exit(121);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 2;
    return !WIFSIGNALED(status) || (WTERMSIG(status) != SIGSEGV && WTERMSIG(status) != SIGBUS);
}
int main(void) {
    uintptr_t headers[3][2] = {
        {(uintptr_t)target0, 0}, {(uintptr_t)target1, 123}, {(uintptr_t)target2, UINTPTR_MAX}
    };
    for (unsigned i = 0; i < 3; ++i) {
        callback = headers[i];
        if (view() != headers[i][0] || dead() != 7) return 3;
        headers[i][1] ^= UINTPTR_MAX;
        if (view() != headers[i][0]) return 4;
    }
    if (null_fault(view) || null_fault(dead)) return 5;
    return 0;
}
`, prefix)
	for _, api := range []string{"GoModule", "GoModuleInContext"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, declarations)
			pkg.Path = "ordinaryglobals"
			ir, err := goFuncvalGlobalRequest(t, pkg, []byte(assembly), arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				text := ir
				if optimized {
					text = x86DwordProductIROptimize(t, ir)
				}
				if strings.Count(text, "load volatile ") != 4 {
					t.Fatal("mutable/nil/dead-result reads disappeared", text)
				}
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR-O2=%t/backend-O%d", optimized, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, execution.llc, execution.compiler,
							"go-funcval-code-word", execution.triple, text, driver, nil, level)
					})
				}
			}
		})
	}
	t.Log("8 actual-host portable C executions, 72 code-word/value checks and 16 nil-fault signals; not original Go/native-x86 execution or callable ABI proof")
}
