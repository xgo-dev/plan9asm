package plan9asm

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestLLVM22RequiredSeparateWasmLinker(t *testing.T) {
	if path := findLLVM22Tool("wasm-ld"); path == "" {
		t.Fatal("required LLVM 22 wasm linker was not found; LLD may be packaged separately from LLVM_CONFIG")
	}
}

func TestLLVM22ConfiguredCompilersCannotFallbackToAnotherInstallation(t *testing.T) {
	bindir := filepath.Join(t.TempDir(), "configured-llvm22", "bin")
	for _, name := range []string{"llc", "clang", "clang++", "llvm-mc", "llvm-objdump", "opt"} {
		t.Run(name, func(t *testing.T) {
			if actual := llvm22ToolCandidates(name, bindir); !reflect.DeepEqual(actual, []string{filepath.Join(bindir, name)}) {
				t.Fatalf("configured compiler acquired a fallback: %v", actual)
			}
		})
	}
}

func TestLLVM22SeparateLinkerCandidatesRetainExactVersion(t *testing.T) {
	bindir := filepath.Join(t.TempDir(), "configured-llvm22", "bin")
	for _, name := range []string{"wasm-ld", "ld.lld", "ld64.lld", "lld-link"} {
		t.Run(name, func(t *testing.T) {
			want := []string{
				filepath.Join(bindir, name), name + "-22", name,
				filepath.Join("/opt/homebrew/opt/lld@22/bin", name),
				filepath.Join("/usr/local/opt/lld@22/bin", name),
			}
			if actual := llvm22ToolCandidates(name, bindir); !reflect.DeepEqual(actual, want) {
				t.Fatalf("separate LLD candidate policy changed: %v", actual)
			}
		})
	}
}

func TestLLVM22VersionMatchingRejectsOtherMajors(t *testing.T) {
	for _, test := range []struct {
		version string
		valid   bool
	}{
		{"Homebrew LLD 22.1.8\n", true},
		{"Debian LLVM version 22.1.8\n", true},
		{"clang version 22.1.8\n", true},
		{"LLD 21.1.8\n", false},
		{"LLD 23.0.0\n", false},
		{"LLD 220.1.0\n", false},
		{"LLVM version 23.0.0\n", false},
		{"clang version 21.1.0\n", false},
	} {
		t.Run(test.version, func(t *testing.T) {
			if llvm22ToolVersionRE.MatchString(test.version) != test.valid {
				t.Fatalf("major version matching changed: %q", test.version)
			}
		})
	}
}
