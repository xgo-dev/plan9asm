//go:build !windows

package main

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestCompileOneRejectsLLCWithoutObject(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "asm_amd64.s")
	if err := os.WriteFile(asm, []byte("TEXT ·run(SB),$0-0\n\tRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath: "example.com/fake",
		Types:   types.NewPackage("example.com/fake", "fake"),
		Imports: map[string]*packages.Package{},
	}
	out := filepath.Join(dir, "asm_amd64.s.ll")
	object := strings.TrimSuffix(out, ".ll") + ".o"
	if err := os.WriteFile(object, []byte("stale object"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := compileOne(
		pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: out},
		false, compileConfig{Enabled: true, LLC: fakeLLC(t, "LLVM version 22.1.8")},
	)
	if err == nil || !strings.Contains(err.Error(), "did not produce a nonempty object") {
		t.Fatalf("compileOne() error = %v, want missing object failure", err)
	}
	if _, err := os.Stat(object); !os.IsNotExist(err) {
		t.Fatalf("stale object was not removed: %v", err)
	}
}

func TestResolveCompileConfigRequiresLLVM22(t *testing.T) {
	llvm22 := fakeLLC(t, "LLVM version 22.1.8")
	cfg, err := resolveCompileConfig(true, llvm22, false, 2)
	if err != nil {
		t.Fatalf("resolveCompileConfig(LLVM 22): %v", err)
	}
	if cfg.LLC != llvm22 {
		t.Fatalf("resolved llc = %q, want %q", cfg.LLC, llvm22)
	}

	llvm23 := fakeLLC(t, "LLVM version 23.0.0")
	if _, err := resolveCompileConfig(true, llvm23, false, 2); err == nil || !strings.Contains(err.Error(), "requires LLVM 22") {
		t.Fatalf("resolveCompileConfig(LLVM 23) error = %v, want LLVM 22 requirement", err)
	}
}

func TestResolveCompileConfigDoesNotFallbackToLLVM23(t *testing.T) {
	dir := t.TempDir()
	writeFakeLLC(t, filepath.Join(dir, "llc"), "LLVM version 23.0.0")
	t.Setenv("PATH", dir)
	if _, err := resolveCompileConfig(true, "", false, 2); err == nil || !strings.Contains(err.Error(), "LLVM 22 llc is not found") {
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
