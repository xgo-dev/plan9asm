//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func x86TerminalPrefixReadC() string {
	var prototypes, names strings.Builder
	for index := range x86TerminalPrefixMechanismFixtures() {
		fmt.Fprintf(&prototypes, "extern void TerminalRead%d(uint64_t *);\n", index)
		fmt.Fprintf(&names, "TerminalRead%d,\n", index)
	}
	return strings.NewReplacer("@PROTOTYPES@", prototypes.String(), "@FUNCTIONS@", names.String()).Replace(`
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
@PROTOTYPES@
int main(void) {
    void (*functions[])(uint64_t *) = {@FUNCTIONS@};
    unsigned observed = 0;
    for (unsigned index = 0; index < sizeof(functions)/sizeof(functions[0]); ++index) {
        for (int valid = 0; valid < 2; ++valid) {
            pid_t child = fork();
            if (child < 0) return 1;
            if (child == 0) {
                struct rlimit no_core = {0, 0};
                if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
                uint64_t value = UINT64_C(0x123456789abcdef0);
                functions[index](valid ? &value : (uint64_t *)0);
                _exit(91);
            }
            int status = 0;
            if (waitpid(child, &status, 0) != child) return 2;
            int expected = valid ? SIGILL : SIGSEGV;
            if (!WIFSIGNALED(status) || WTERMSIG(status) != expected) {
                fprintf(stderr, "terminal-prefix index=%u valid=%d status=%x expected=%d\n", index, valid, status, expected);
                return 3;
            }
            ++observed;
        }
    }
    printf("terminal-prefix faults %u\n", observed);
    return 0;
}
`)
}

func TestCrossLinuxRuntimeMatrixX86TerminalPrefixReadFaultOrder(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	source, declarations := x86TerminalPrefixReadSource()
	var names strings.Builder
	for index := range x86TerminalPrefixMechanismFixtures() {
		fmt.Fprintf(&names, "TerminalRead%d,\n", index)
	}
	driver := strings.Replace(`package main
import("os";"strconv";"syscall")
func main() {
    if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil { panic(err) }
    index, err := strconv.Atoi(os.Args[1]); if err != nil { panic(err) }
    functions := []func(*uint64){@FUNCTIONS@}
    value := uint64(0x123456789abcdef0)
    pointer := &value
    if os.Args[2] == "null" { pointer = nil }
    functions[index](pointer)
    os.Exit(91)
}
`, "@FUNCTIONS@", names.String(), 1)
	goos := runtime.GOOS
	if strings.Contains(execution.triple, "linux") {
		goos = "linux"
	}
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), goos, "amd64", "package main\n"+declarations, source, driver)
	for index := range x86TerminalPrefixMechanismFixtures() {
		for _, address := range []string{"null", "valid"} {
			t.Run(fmt.Sprintf("original/%d/%s", index, address), func(t *testing.T) {
				arguments := execution.command(original, fmt.Sprint(index), address)
				stage, cancel := runtimeOracleStageContext(t)
				command := exec.CommandContext(stage, arguments[0], arguments[1:]...)
				command.Env = append(os.Environ(), "GOTRACEBACK=system")
				output, err := runtimeOracleCombinedOutput(stage, command)
				cancel()
				exit, completed := err.(*exec.ExitError)
				signal := "SIGSEGV"
				if address == "valid" {
					signal = "SIGILL: illegal instruction"
				}
				if !completed || exit.ProcessState == nil || !exit.ProcessState.Exited() || exit.ExitCode() != 2 ||
					!strings.Contains(string(output), signal) || !strings.Contains(string(output), fmt.Sprint("main.TerminalRead", index)) {
					t.Fatalf("original Go prefix/fault order lost a completed exact signal: %v\n%s", err, output)
				}
			})
		}
	}
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
		if err != nil {
			t.Fatal("original prefix functions rejected", api, err)
		}
		for _, pipeline := range []struct{ name, level, ir string }{
			{"backend-O0", "-O0", ir}, {"backend-O2", "-O2", ir},
			{"IR-O2-backend-O2", "-O2", x86UndefinedTrapOptimizedIR(t, ir)},
		} {
			t.Run(api+"/"+pipeline.name, func(t *testing.T) {
				output := execution.compileAndRunLLVM(t, "terminal-prefix", pipeline.ir, x86TerminalPrefixReadC(), pipeline.level)
				if string(output) != "terminal-prefix faults 16\n" {
					t.Fatalf("independent eight-mechanism null/valid-pointer fault observations: %q", output)
				}
			})
		}
	}
}
