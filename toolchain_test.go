package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func findLlcAndClang(t *testing.T) (llc, clang string, ok bool) {
	t.Helper()
	llc = findLLVM22Tool("llc")
	clang = findLLVM22Tool("clang")

	return llc, clang, llc != "" && clang != ""
}

var llvm22ToolVersionRE = regexp.MustCompile(`(?im)(?:\bLLVM|\bclang) version 22(?:\.|$)|\bLLD 22(?:\.|$)`)

func findLLVM22Tool(name string) string {
	bindir := ""
	if llvmConfig := os.Getenv("LLVM_CONFIG"); llvmConfig != "" {
		out, err := llvm22ToolOutput(llvmConfig, "--version")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(out)), "22.") {
			return ""
		}
		out, err = llvm22ToolOutput(llvmConfig, "--bindir")
		if err != nil {
			return ""
		}
		bindir = strings.TrimSpace(string(out))
		if bindir == "" {
			return ""
		}
	}
	for _, candidate := range llvm22ToolCandidates(name, bindir) {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		out, err := llvm22ToolOutput(path, "--version")
		if err == nil && llvm22ToolVersionRE.Match(out) {
			return path
		}
	}
	return ""
}

func llvm22ToolOutput(executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, executable, args...))
}

func llvm22ToolCandidates(name, bindir string) []string {
	var candidates []string
	if bindir != "" {
		candidates = append(candidates, filepath.Join(bindir, name))
		// LLD is a distinct package in several distributions. The configured
		// LLVM compiler remains authoritative; only linker tools may use an
		// independently version-checked LLVM 22 installation.
		switch name {
		case "wasm-ld", "ld.lld", "ld64.lld", "lld-link":
			candidates = append(candidates, name+"-22", name,
				filepath.Join("/opt/homebrew/opt/lld@22/bin", name),
				filepath.Join("/usr/local/opt/lld@22/bin", name))
		}
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
	return candidates
}
