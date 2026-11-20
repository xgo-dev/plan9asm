package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

type x86FloatCompareExecution struct {
	llc, triple   string
	compiler      []string
	prefix        []string
	preserveArgv0 bool
}

func (execution x86FloatCompareExecution) command(executable string, arguments ...string) []string {
	command := append([]string(nil), execution.prefix...)
	command = append(command, executable)
	if execution.preserveArgv0 {
		command = append(command, executable)
	}
	return append(command, arguments...)
}

// This is a test-only execution route, not a production ISA permission. The
// pinned binfmt artifact's special argv transport applies only after its exact
// binary identity is checked; Rosetta and ordinary native execution differ.
func x86FloatCompareExecutionTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm64" {
		llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
		return x86FloatCompareExecution{llc: llc, triple: triple,
			compiler: []string{clang, "-target", triple}, prefix: prefix}
	}
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang required")
	}
	qemu, err := exec.LookPath("qemu-x86_64")
	if err != nil {
		t.Fatal("required explicit QEMU x86 execution:", err)
	}
	contents, err := os.ReadFile(qemu)
	if err != nil {
		t.Fatal(err)
	}
	// Official linux-arm64 deploy/v10.2.3-68 release, archive ca19f8d2...;
	// the setup driver separately authenticates the complete archive checksum.
	const pinnedSHA = "f04e3597ebf2ba6fe98bfb8f453dcbb1b767695e0283ceb7fa265af94d66fc19"
	if actual := fmt.Sprintf("%x", sha256.Sum256(contents)); actual != pinnedSHA {
		t.Fatalf("QEMU binary identity: got %s, want %s", actual, pinnedSHA)
	}
	version := x86FloatCompareCaptureCommand(t, exec.Command(qemu, "--version"))
	if !strings.HasPrefix(string(version), "qemu-x86_64 version 10.2.3 ") {
		t.Fatalf("required QEMU10.2.3: %s", version)
	}
	compiler, err := exec.LookPath("x86_64-linux-gnu-gcc")
	if err != nil {
		t.Fatal("required AMD64 ELF cross compiler:", err)
	}
	if info, err := os.Stat("/usr/x86_64-linux-gnu"); err != nil || !info.IsDir() {
		t.Fatalf("required AMD64 guest sysroot: %v", err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{compiler, "-no-pie"},
		prefix:   []string{qemu, "-cpu", "max", "-L", "/usr/x86_64-linux-gnu"}, preserveArgv0: true}
	t.Logf("explicit authenticated guest transport=%q (not Rosetta/binfmt execution)", execution.prefix)
	return execution
}

func (execution x86FloatCompareExecution) compileC(t *testing.T, source, output string) {
	t.Helper()
	command := append([]string(nil), execution.compiler...)
	process := runtimeOracleProcessSource(t, filepath.Dir(output))
	command = append(command, "-O2", source, process, "-o", output)
	x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
}

func (execution x86FloatCompareExecution) run(t *testing.T, executable string, arguments ...string) []byte {
	t.Helper()
	command := execution.command(executable, arguments...)
	return x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
}

// Keep the authenticated guest argv transport through the final executable,
// not merely through the original-Go preflight. Each external stage has its
// own bounded lifecycle; no LLVM module or context survives between fixtures.
func (execution x86FloatCompareExecution) compileAndRunLLVM(t *testing.T, name, ir, main, level string) []byte {
	t.Helper()
	return execution.run(t, execution.compileLLVM(t, name, ir, main, level))
}

// The caller owns this test's temporary directory until all independent
// invocations finish. Fault observers need the executable, not a helper that
// treats every genuine native exception as an ordinary command failure.
func (execution x86FloatCompareExecution) compileLLVM(t *testing.T, name, ir, main, level string) string {
	t.Helper()
	if execution.llc == "" || len(execution.compiler) == 0 {
		t.Fatal("comparison runtime requires its actual LLVM22 and C compiler")
	}
	if level != "-O0" && level != "-O2" {
		t.Fatalf("unsupported comparison optimization level %q", level)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, name+".ll")
	object := filepath.Join(dir, name+".o")
	source := filepath.Join(dir, "main.c")
	executable := filepath.Join(dir, gotoolchain.HostExecutable("comparison"))
	if strings.Contains(execution.triple, "windows") {
		main = "int _fltused = 0;\n" + main
	}
	process := runtimeOracleProcessSource(t, dir)
	for path, contents := range map[string]string{input: ir, source: main} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	x86FloatCompareCaptureCommand(t, exec.Command(execution.llc, level,
		"-mtriple="+execution.triple, "-relocation-model=pic", "-filetype=obj", input, "-o", object))
	compiler := append([]string(nil), execution.compiler...)
	compiler = append(compiler, object, source, process, "-O2", "-o", executable)
	if !strings.Contains(execution.triple, "windows") {
		compiler = append(compiler, "-lm")
	}
	x86FloatCompareCaptureCommand(t, exec.Command(compiler[0], compiler[1:]...))
	return executable
}

func (execution x86FloatCompareExecution) requireAVX(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "isa.c"), filepath.Join(dir, "isa")
	const preflight = `#include <stdio.h>
int main(void) {
 __builtin_cpu_init();
 int avx=!!__builtin_cpu_supports("avx");
 int avx2=!!__builtin_cpu_supports("avx2");
 int avx512=!!__builtin_cpu_supports("avx512f");
 printf("AVX=%d AVX2=%d AVX512F=%d\n",avx,avx2,avx512);
 return avx?0:1;
}
`
	if err := os.WriteFile(source, []byte(preflight), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	t.Logf("actual guest CPUID/XCR0 preflight: %s", strings.TrimSpace(string(execution.run(t, executable))))
}

func TestX86FloatingCompareExecutionTransport(t *testing.T) {
	for _, test := range []struct {
		name      string
		execution x86FloatCompareExecution
		want      []string
	}{
		{"native", x86FloatCompareExecution{}, []string{"/guest", "numeric", "with space"}},
		{"rosetta", x86FloatCompareExecution{prefix: []string{"arch", "-x86_64"}},
			[]string{"arch", "-x86_64", "/guest", "numeric", "with space"}},
		{"pinned", x86FloatCompareExecution{prefix: []string{"qemu", "-cpu", "max"}, preserveArgv0: true},
			[]string{"qemu", "-cpu", "max", "/guest", "/guest", "numeric", "with space"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			arguments := []string{"numeric", "with space"}
			before := append([]string(nil), test.execution.prefix...)
			if actual := test.execution.command("/guest", arguments...); !reflect.DeepEqual(actual, test.want) {
				t.Fatalf("guest arguments: got %q, want %q", actual, test.want)
			}
			if !reflect.DeepEqual(before, test.execution.prefix) || !reflect.DeepEqual(arguments, []string{"numeric", "with space"}) {
				t.Fatal("execution argument construction mutated its inputs")
			}
		})
	}
}

func x86FloatCompareVerifyArguments(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":  "module comparearguments\n\ngo 1.20\n",
		"main.go": "package main\nimport(\"fmt\";\"os\")\nfunc main(){fmt.Printf(\"%q\\n\",os.Args)}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(dir, gotoolchain.HostExecutable("arguments"))
	command := exec.Command("go", "build", "-p=2", "-o", executable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0",
		"GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	for _, arguments := range [][]string{nil, {"numeric", "with space"}} {
		want := fmt.Sprintf("%q\n", append([]string{executable}, arguments...))
		if actual := string(execution.run(t, executable, arguments...)); actual != want {
			t.Fatalf("actual guest argument witness: got %q, want %q", actual, want)
		}
	}
}
