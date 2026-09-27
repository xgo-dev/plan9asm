package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func findLlcAndClang(t *testing.T) (llc, clang string, ok bool) {
	t.Helper()
	llc = findLLVM22Tool("llc")
	clang = findLLVM22Tool("clang")

	return llc, clang, llc != "" && clang != ""
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
	} else {
		candidates = append(candidates, name+"-22", name)
		// Homebrew keeps versioned LLVM/LLD installations outside PATH. Keep
		// these explicit candidates version-checked so an unversioned LLVM 23
		// tool can never become a silent fallback for the LLVM 22 tests.
		for _, prefix := range []string{
			"/opt/homebrew/opt/llvm@22/bin",
			"/opt/homebrew/opt/lld@22/bin",
			"/usr/local/opt/llvm@22/bin",
			"/usr/local/opt/lld@22/bin",
		} {
			candidates = append(candidates, filepath.Join(prefix, name))
		}
	}
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
