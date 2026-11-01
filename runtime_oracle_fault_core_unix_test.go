//go:build unix

package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func runtimeOracleFaultC(t *testing.T, name string) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(value, "fork()") {
			found = append(found, value)
		}
		return true
	})
	if len(found) != 1 {
		t.Fatalf("%s: expected one actual fault-child C source, found %d", name, len(found))
	}
	return found[0]
}

func runtimeOracleFaultCorePolicy(source string) error {
	child := regexp.MustCompile(`if\s*\(\s*(?:child\s*==\s*0|!child)\s*\)\s*\{`)
	policy := regexp.MustCompile(
		`^\s*struct\s+rlimit\s+no_core\s*=\s*\{\s*0\s*,\s*0\s*\}\s*;` +
			`\s*if\s*\(\s*setrlimit\s*\(\s*RLIMIT_CORE\s*,\s*&no_core\s*\)` +
			`\s*\)\s*_exit\s*\(\s*120\s*\)\s*;`)
	branches := child.FindAllStringIndex(source, -1)
	// This is a bounded check for the actual C fixture templates, not a C
	// parser. An unregistered child predicate must not hide another fork.
	fork := regexp.MustCompile(`\bfork\s*\(\s*\)`)
	forks := fork.FindAllStringIndex(source, -1)
	if len(branches) == 0 || len(branches) != len(forks) {
		return fmt.Errorf("each actual fork needs one registered child branch: forks=%d branches=%d", len(forks), len(branches))
	}
	for index, branch := range branches {
		if !policy.MatchString(source[branch[1]:]) {
			return fmt.Errorf("fault child %d must first set both core limits to zero and check failure before invoking its oracle", index+1)
		}
	}
	return nil
}

func TestRuntimeOracleFaultChildrenDisableCoreDumps(t *testing.T) {
	for _, name := range []string{
		"amd64_packed_shift_native_count_runtime_test.go",
		"amd64_undefined_trap_runtime_unix_test.go",
		"amd64_cpu_query_runtime_unix_test.go",
		"amd64_dword_product_fault_runtime_unix_test.go",
	} {
		t.Run(name, func(t *testing.T) {
			source := runtimeOracleFaultC(t, name)
			if err := runtimeOracleFaultCorePolicy(source); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeOracleFaultCorePolicyChecksEveryChild(t *testing.T) {
	const valid = `struct rlimit no_core = {0, 0};
if (setrlimit(RLIMIT_CORE, &no_core)) _exit(120);
oracle();
`
	branch := func(condition, body string) string {
		return "pid_t child = fork();\nif (" + condition + ") {\n" + body + "}\n"
	}
	first := branch("child == 0", valid)
	cases := []struct {
		name   string
		source string
		valid  bool
	}{
		{"no_child", "", false},
		{"one_checked_child", first, true},
		{"two_checked_children", first + branch("!child", valid), true},
		{"three_checked_children", first + first + first, true},
		{"first_missing_policy", branch("child == 0", "oracle();\n") + first, false},
		{"second_missing_policy", first + branch("child == 0", "oracle();\n"), false},
		{"third_missing_policy", first + first + branch("!child", "oracle();\n"), false},
		{"second_unchecked_limit", first + branch("!child", "struct rlimit no_core = {0, 0};\nsetrlimit(RLIMIT_CORE, &no_core);\noracle();\n"), false},
		{"second_nonzero_soft_limit", first + branch("!child", strings.Replace(valid, "{0, 0}", "{1, 0}", 1)), false},
		{"second_nonzero_hard_limit", first + branch("!child", strings.Replace(valid, "{0, 0}", "{0, 1}", 1)), false},
		{"second_wrong_resource", first + branch("!child", strings.Replace(valid, "RLIMIT_CORE", "RLIMIT_CPU", 1)), false},
		{"second_wrong_failure_exit", first + branch("!child", strings.Replace(valid, "_exit(120)", "_exit(0)", 1)), false},
		{"second_late_policy", first + branch("!child", "oracle();\n"+valid), false},
		{"second_unregistered_branch", first + branch("child != 0", valid), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := runtimeOracleFaultCorePolicy(test.source)
			if (err == nil) != test.valid {
				t.Fatalf("fault-child resource policy: err=%v, want valid=%t", err, test.valid)
			}
		})
	}
}

// Execute the actual legacy shift fault helper with a harmless callback. Inheriting
// a nonzero core limit fails without raising a signal or creating a core file.
func TestRuntimeOracleFaultChildCoreLimitInheritance(t *testing.T) {
	_, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 tools required")
	}
	source := x86PackedShiftLegacyCountCHeader +
		runtimeOracleFaultC(t, "amd64_packed_shift_native_count_runtime_test.go")
	source += `
#include <sys/resource.h>

static void inspect_limits(uint8_t *out, const uint8_t *data, const uint8_t *count, uint64_t seed) {
    (void)out;
    (void)data;
    (void)count;
    (void)seed;
    struct rlimit limit;
    if (getrlimit(RLIMIT_CORE, &limit) || limit.rlim_cur || limit.rlim_max) _exit(91);
    _exit(0);
}

int main(int argc, char **argv) {
    struct rlimit original, parent, after;
    if (getrlimit(RLIMIT_CORE, &original)) return 10;
    parent = original;
    if (argc > 1) {
        parent.rlim_cur = parent.rlim_max = 0;
    } else {
        parent.rlim_cur = parent.rlim_max < 4096 ? parent.rlim_max : 4096;
    }
    if (setrlimit(RLIMIT_CORE, &parent)) return 11;
    uint8_t count[32] = {0};
    int status = observe_count(inspect_limits, 0, 0, 0, count, 0);
    int result = status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    if (getrlimit(RLIMIT_CORE, &after) || after.rlim_cur != parent.rlim_cur ||
        after.rlim_max != parent.rlim_max) return 13;
    if (argc == 1 && setrlimit(RLIMIT_CORE, &original)) return 14;
    fprintf(stdout, "parent=%llu/%llu child-status=%d\n",
        (unsigned long long)parent.rlim_cur, (unsigned long long)parent.rlim_max, result);
    return result;
}
`
	directory := t.TempDir()
	cPath, executable := filepath.Join(directory, "core.c"), filepath.Join(directory, "core")
	if err := os.WriteFile(cPath, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(ctx, runtimeOracleNativeCCommand(t, ctx, clang, "-O2", cPath, "-o", executable))
	cancel()
	if err != nil {
		t.Fatalf("compile actual fault helper: %v\n%s", err, output)
	}
	for _, mode := range []string{"inherited", "hard-zero"} {
		t.Run(mode, func(t *testing.T) {
			var arguments []string
			if mode == "hard-zero" {
				arguments = append(arguments, mode)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, executable, arguments...))
			cancel()
			if err != nil {
				t.Fatalf("actual child resource observation: %v\n%s", err, output)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

// CMPXCHG launches the C driver directly instead of forking. Exercise that
// driver's actual entry setup with a harmless callback, before any real fault.
func TestX86CMPXCHGFaultChildCoreLimit(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const callback = `
static void inspect_limits(unsigned char *p) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_CORE, &limit) || limit.rlim_cur || limit.rlim_max) exit(91);
    *p = 4;
}
`
	source := fmt.Sprintf(x86CMPXCHGFaultReference, "", callback,
		"{inspect_limits, inspect_limits, 1, 0},")
	executable := execution.compileLLVM(t, "cmpxchg-core-limit", "", source, "-O2")
	for _, original := range []int{0, 1} {
		got, err := x86CMPXCHGObserveFault(t, execution, executable, 0, 0, original)
		if err != nil || got != "return" {
			t.Fatalf("actual direct child core limits, original=%d: %s, %v", original, got, err)
		}
	}
}

func TestX86MemoryFaultChildCoreLimit(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	const callback = `
static int inspect_limits(const uint8_t *p) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_CORE, &limit) || limit.rlim_cur || limit.rlim_max) return 91;
    return *p != (uint8_t)((page - 4) * 13 + 17);
}
`
	source := x86MemoryFaultDriver(callback, "{inspect_limits, 4, 3},")
	executable := execution.compileLLVM(t, "memory-core-limit", "", source, "-O2")
	if got := x86ObserveMemoryFault(t, execution, executable, 0, 2, 0); got != "return" {
		t.Fatalf("direct child did not retain zero core limits: %s", got)
	}
}
