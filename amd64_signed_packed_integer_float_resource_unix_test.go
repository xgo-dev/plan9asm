//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/scanner"
)

func TestX86SignedPackedFloatFaultChildDisablesCore(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM22 clang required")
	}
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "resource.c"), filepath.Join(dir, "resource")
	if err := os.WriteFile(source, []byte(x86SignedPackedFloatChildOracle+x86SignedPackedFloatCoreLimitObserver), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	output, err := runtimeOracleCombinedOutput(ctx, runtimeOracleNativeCCommand(t, ctx, clang, "-std=c11", "-O2", source, "-o", executable))
	cancel()
	if err != nil {
		t.Fatalf("compile core-limit observer: %v\n%s", err, output)
	}
	for _, mode := range []string{"inherited", "hard-zero"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, executable, mode))
			if err != nil {
				t.Fatalf("core-limit child: %v\n%s", err, output)
			}
			if !strings.HasPrefix(string(output), "CORE_LIMIT_CHILD_EXECUTED parent_soft=") {
				t.Fatalf("resource observer did not execute: %q", output)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

// This is a source consumer, not a search for a setrlimit string: C comments
// and literals are single tokens, and the policy must be the first statements
// in the actual fork-child branch before either callback or canary writes.
func TestX86SignedPackedFloatFaultChildCorePolicySource(t *testing.T) {
	if err := x86SignedPackedFloatValidateChildCorePolicy(x86SignedPackedFloatChildOracle); err != nil {
		t.Fatal(err)
	}
	// The real native callback must still traverse that checked fork branch.
	tokens := strings.Join(x86SignedPackedFloatCTokens(x86SignedPackedFloatFaultOracle), " ")
	call := strings.Join(x86SignedPackedFloatCTokens("return fault_child(invoke_conversion,&request,csr,expected);"), " ")
	if strings.Count(tokens, call) != 1 {
		t.Fatal("native-fault callback bypasses or ambiguously uses the child resource policy")
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"removed", "struct rlimit core = {0,0};", ""},
		{"comment only", "struct rlimit core = {0,0};", "/* struct rlimit core = {0,0}; */"},
		{"nonzero", "{0,0}", "{1,0}"},
		{"unchecked", "if (setrlimit(RLIMIT_CORE,&core) != 0) _exit(90);", "setrlimit(RLIMIT_CORE,&core);"},
		{"success on error", "_exit(90)", "_exit(0)"},
		{"late", "unsigned char out[18];", "unsigned char out[18];\nstruct rlimit core = {0,0};\nif (setrlimit(RLIMIT_CORE,&core) != 0) _exit(90);"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			source := x86SignedPackedFloatChildOracle
			if mutation.name == "late" {
				source = strings.Replace(source, "struct rlimit core = {0,0};\n        if (setrlimit(RLIMIT_CORE,&core) != 0) _exit(90);\n        ", "", 1)
			}
			source = strings.Replace(source, mutation.old, mutation.replacement, 1)
			if err := x86SignedPackedFloatValidateChildCorePolicy(source); err == nil {
				t.Fatal("invalid child policy passed its structural consumer")
			}
		})
	}
}

func x86SignedPackedFloatValidateChildCorePolicy(source string) error {
	tokens := x86SignedPackedFloatCTokens(source)
	branch := x86SignedPackedFloatCTokens("if (pid == 0) {")
	policy := x86SignedPackedFloatCTokens("struct rlimit core = {0,0}; if (setrlimit(RLIMIT_CORE,&core) != 0) _exit(90);")
	matches := 0
	for index := 0; index+len(branch) <= len(tokens); index++ {
		if strings.Join(tokens[index:index+len(branch)], " ") != strings.Join(branch, " ") {
			continue
		}
		matches++
		start := index + len(branch)
		if start+len(policy) > len(tokens) || strings.Join(tokens[start:start+len(policy)], " ") != strings.Join(policy, " ") {
			return fmt.Errorf("actual fault_child branch lacks its initial checked core-limit policy")
		}
	}
	if matches != 1 {
		return fmt.Errorf("ambiguous actual fork-child branch: %d", matches)
	}
	return nil
}

func x86SignedPackedFloatCTokens(source string) []string {
	var lexer scanner.Scanner
	lexer.Init(strings.NewReader(source))
	lexer.Mode = scanner.GoTokens
	var tokens []string
	for lexer.Scan() != scanner.EOF {
		tokens = append(tokens, lexer.TokenText())
	}
	return tokens
}

// Only this disposable C parent changes its limits. An already-safe hard=0
// environment still forks and checks both child limits; it is not a Skip.
// No instruction or signal capable of generating a core is invoked here.
const x86SignedPackedFloatCoreLimitObserver = `
static void observe_limits(void *out, const void *input, unsigned csr) {
    (void)input;
    (void)csr;
    struct rlimit observed;
    if (getrlimit(RLIMIT_CORE,&observed)) _exit(92);
    if (observed.rlim_cur || observed.rlim_max) {
        fprintf(stderr,"inherited child core soft=%llu hard=%llu\n",
            (unsigned long long)observed.rlim_cur,(unsigned long long)observed.rlim_max);
    }
    const uint64_t limits[2] = {observed.rlim_cur,observed.rlim_max};
    memcpy(out,limits,sizeof(limits));
}

int main(int argc, char **argv) {
    if (argc != 2) return 8;
    if (!strcmp(argv[1],"hard-zero")) {
        const struct rlimit zero = {0,0};
        if (setrlimit(RLIMIT_CORE,&zero)) return 9;
    } else if (strcmp(argv[1],"inherited")) return 8;
    struct rlimit saved, raised, unchanged, restored;
    if (getrlimit(RLIMIT_CORE,&saved)) return 10;
    raised = saved;
    raised.rlim_cur = saved.rlim_max == RLIM_INFINITY || saved.rlim_max > 4096 ? 4096 : saved.rlim_max;
    if (setrlimit(RLIMIT_CORE,&raised)) return 11;

    const unsigned char no_core[16] = {0};
    int status = fault_child(observe_limits,0,0,no_core);
    int read_error = getrlimit(RLIMIT_CORE,&unchanged);
    int restore_error = setrlimit(RLIMIT_CORE,&saved);
    if (read_error || restore_error || getrlimit(RLIMIT_CORE,&restored)) return 12;
    if (unchanged.rlim_cur != raised.rlim_cur || unchanged.rlim_max != raised.rlim_max ||
        restored.rlim_cur != saved.rlim_cur || restored.rlim_max != saved.rlim_max) return 13;
    if (status) {
        fprintf(stderr,"child policy status=%d parent soft=%llu hard=%llu\n",status,
            (unsigned long long)raised.rlim_cur,(unsigned long long)raised.rlim_max);
        return 14;
    }
    printf("CORE_LIMIT_CHILD_EXECUTED parent_soft=%llu child_soft=0 child_hard=0 parent_restored=1\n",
        (unsigned long long)raised.rlim_cur);
    return 0;
}
`
