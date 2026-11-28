package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func requireLLVM22Tool(t *testing.T, name string) string {
	t.Helper()
	path := findLLVM22Tool(name)
	if path == "" {
		t.Fatalf("LLVM 22 %s required", name)
	}
	return path
}

func requireLlcAndClang(t *testing.T) (string, string) {
	t.Helper()
	return requireLLVM22Tool(t, "llc"), requireLLVM22Tool(t, "clang")
}

var llvm22ToolVersionRE = regexp.MustCompile(`(?im)(?:\bLLVM|\bclang) version 22(?:\.|$)|\bLLD 22(?:\.|$)`)

func findLLVM22Tool(name string) string {
	var candidates []string
	if llvmConfig := os.Getenv("LLVM_CONFIG"); llvmConfig != "" {
		out, err := exec.Command(llvmConfig, "--version").Output()
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "22.") {
			return ""
		}
		out, err = exec.Command(llvmConfig, "--bindir").Output()
		if err != nil {
			return ""
		}
		candidates = append(candidates, filepath.Join(strings.TrimSpace(string(out)), name))
	}
	// Also search PATH candidates (e.g. Homebrew packages lld@22 separately
	// from llvm@22), still enforcing the exact LLVM/LLD 22 version regex below.
	candidates = append(candidates, name+"-22", name)
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		out, err := exec.Command(path, "--version").CombinedOutput()
		if err == nil && llvm22ToolVersionRE.Match(out) {
			return path
		}
	}
	return ""
}

func verifyLLVMWithTargetLLC(t *testing.T, ir string, triple string, extraLLCArgs ...string) {
	t.Helper()
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}
	cmd := exec.Command(opt, "-passes=verify", "-disable-output", "-")
	cmd.Stdin = strings.NewReader(ir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("opt verify (%s) failed: %v\n%s\nIR:\n%s", triple, err, out, ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	object := filepath.Join(t.TempDir(), "probe.o")
	args := []string{"-mtriple=" + triple, "-filetype=obj", "-o", object, "-"}
	args = append(args, extraLLCArgs...)
	cmd = exec.Command(llc, args...)
	cmd.Stdin = strings.NewReader(ir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("llc (%s) failed: %v\n%s\nIR:\n%s", triple, err, out, ir)
	}
	info, err := os.Stat(object)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("llc emitted an empty object")
	}

}

func runOptO2(t *testing.T, ir string) string {
	t.Helper()
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}
	cmd := exec.Command(opt, "-O2", "-S", "-")
	cmd.Stdin = strings.NewReader(ir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opt -O2 failed: %v\n%s\nIR:\n%s", err, out, ir)
	}
	return string(out)
}

func extractLLVMFuncBody(t *testing.T, ir, fnName string) string {
	t.Helper()
	needle := "@" + fnName + "("
	idx := strings.Index(ir, needle)
	if idx < 0 {
		t.Fatalf("function %s not found in IR:\n%s", fnName, ir)
	}
	start := strings.Index(ir[idx:], "{")
	if start < 0 {
		t.Fatalf("function %s missing body open brace", fnName)
	}
	rest := ir[idx+start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("function %s missing body close brace", fnName)
	}
	return rest[:end+2]
}
