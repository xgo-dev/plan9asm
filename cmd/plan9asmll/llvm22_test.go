//go:build !windows

package main

import (
	"go/types"

	"golang.org/x/tools/go/packages"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCompileConfigRequiresLLVM22(t *testing.T) {
	llvm22 := fakeLLC(t, "LLVM version 22.1.8")
	cfg, err := resolveCompileConfig(true, llvm22, false)
	if err != nil {
		t.Fatalf("resolveCompileConfig(LLVM 22): %v", err)
	}
	if cfg.LLC != llvm22 {
		t.Fatalf("resolved llc = %q, want %q", cfg.LLC, llvm22)
	}

	llvm23 := fakeLLC(t, "LLVM version 23.0.0")
	if _, err := resolveCompileConfig(true, llvm23, false); err == nil || !strings.Contains(err.Error(), "requires LLVM 22") {
		t.Fatalf("resolveCompileConfig(LLVM 23) error = %v, want LLVM 22 requirement", err)
	}
}

func TestResolveCompileConfigDoesNotFallbackToLLVM23(t *testing.T) {
	dir := t.TempDir()
	writeFakeLLC(t, filepath.Join(dir, "llc"), "LLVM version 23.0.0")
	t.Setenv("PATH", dir)
	if _, err := resolveCompileConfig(true, "", false); err == nil || !strings.Contains(err.Error(), "LLVM 22 llc is not found") {
		t.Fatalf("resolveCompileConfig(PATH llc=23) error = %v, want no LLVM 22 error", err)
	}
}

func fakeLLC(t *testing.T, version string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "llc")
	writeFakeLLC(t, path, version)
	return path
}

func writeFakeLLC(t *testing.T, path, version string) {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestCompileOneRejectsNoObjectOutput(t *testing.T) {
	dir := t.TempDir()
	src, out := filepath.Join(dir, "empty.s"), filepath.Join(dir, "empty.ll")
	if err := os.WriteFile(src, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.o"), []byte("old build"), 0600); err != nil {
		t.Fatal(err)
	}
	p := types.NewPackage("example", "example")
	pkg := &packages.Package{PkgPath: p.Path(), Types: p, TypesSizes: types.SizesFor("gc", "amd64")}
	cfg := compileConfig{Enabled: true, KeepObj: true, LLC: fakeLLC(t, "LLVM version 22.1.8")}
	if err := compileOne(pkg, "linux", "amd64", "x86_64-unknown-linux-gnu", asmTask{AsmFile: src, OutLL: out}, false, cfg); err == nil || !strings.Contains(err.Error(), "produced no object") {
		t.Fatalf("zero-exit compiler without current output: %v", err)
	}
}
