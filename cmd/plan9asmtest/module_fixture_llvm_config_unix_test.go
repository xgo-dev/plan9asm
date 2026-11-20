//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func moduleFixtureLLVMConfig(t *testing.T) string {
	t.Helper()
	binary, err := resolveCIConfigExecutable()
	if err != nil {
		t.Fatal("required LLVM 22 configuration:", err)
	}
	data, err := moduleDependencyCommand(context.Background(), config{Timeout: time.Minute},
		filepath.Join(t.TempDir(), "llvm-config-version"), binary, "--version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(data)), "22.") {
		t.Fatalf("fixture requires actual LLVM 22: %v\n%s", err, data)
	}
	// A distro's /usr/bin/llvm-config-22 is commonly a symlink. Its directory
	// also contains Node, so it cannot stand in for the isolated LLVM bin in
	// the missing-Node fixture. Preserve the same selected executable/inode.
	physical, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	return physical
}

func TestModuleLLVMConfigSelectionMatchesActualScope(t *testing.T) {
	binary := moduleFixtureLLVMConfig(t)
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for _, name := range []string{"llvm-config", "llvm-config-22", "explicit-config"} {
		if err := os.Symlink(binary, filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", directory)
	for _, row := range []struct{ requested, selected string }{
		{"", "llvm-config-22"},
		{"explicit-config", "explicit-config"},
		{filepath.Join(directory, "explicit-config"), "explicit-config"},
	} {
		t.Run(row.requested, func(t *testing.T) {
			t.Setenv("LLVM_CONFIG", row.requested)
			got, err := resolveCIConfigExecutable()
			if err != nil || got != filepath.Join(directory, row.selected) {
				t.Fatalf("selected %q, want %q: %v", got, row.selected, err)
			}
		})
	}
	t.Setenv("LLVM_CONFIG", "missing-explicit-config")
	if _, err := resolveCIConfigExecutable(); err == nil {
		t.Fatal("explicit missing config fell back to installed LLVM")
	}
	t.Setenv("LLVM_CONFIG", "")
	if err := os.Remove(filepath.Join(directory, "llvm-config-22")); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveCIConfigExecutable(); err != nil || got != filepath.Join(directory, "llvm-config") {
		t.Fatal("unversioned actual LLVM 22 is unavailable:", got, err)
	}
	if err := os.Remove(filepath.Join(directory, "llvm-config")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCIConfigExecutable(); err == nil {
		t.Fatal("missing required config accepted")
	}
}
