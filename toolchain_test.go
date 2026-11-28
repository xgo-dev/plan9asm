//go:build !llgo
// +build !llgo

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
