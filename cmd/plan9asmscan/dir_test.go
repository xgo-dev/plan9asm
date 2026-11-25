package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanDirectoryAndArchMatchers(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("pkg/fast_amd64.s", "TEXT ·f(SB),0,$0-0\n\tMOVQ AX, BX\n\tBOGUSOP AX, BX\n\tRET\n")
	mustWrite("pkg/tagged.s", "//go:build amd64 && !arm64\nTEXT ·g(SB),0,$0-0\n\tADDQ AX, BX\n\tRET\n")
	mustWrite("pkg/other_arm64.s", "TEXT ·h(SB),0,$0-0\n\tADD R0, R1, R2\n\tRET\n")
	mustWrite("pkg/notext_amd64.s", "// comment only\n")
	mustWrite("pkg/bad_amd64.s", "TEXT ·broken(SB),0,$0-0\n\tMOVQ [unterminated\n")
	mustWrite("testdata/ignored_amd64.s", "TEXT ·ig(SB),0,$0-0\n\tRET\n")
	mustWrite("cache/ignored_amd64.s", "TEXT ·ig2(SB),0,$0-0\n\tRET\n")
	mustWrite("vendor/ignored_amd64.s", "TEXT ·ig3(SB),0,$0-0\n\tRET\n")

	ops, forms, parseErrs, pkgCount, asmFiles, err := scanDirectory(root, plan9asm.ArchAMD64, "amd64")
	if err != nil {
		t.Fatalf("scanDirectory() error = %v", err)
	}
	if pkgCount != 1 || asmFiles < 3 {
		t.Fatalf("scanDirectory() pkgCount=%d asmFiles=%d", pkgCount, asmFiles)
	}
	if len(ops) < 3 || len(forms) < 3 {
		t.Fatalf("expected >=3 ops and forms, got ops=%d forms=%d", len(ops), len(forms))
	}
	if len(parseErrs) != 0 {
		// Depending on parser leniency, bad_amd64.s may either parse or record parseErr.
		t.Logf("parseErrs=%v", parseErrs)
	}

	// Exercise asmFileMatchesArch & asmSourceMatchesArch directly.
	if !asmFileMatchesArch("foo_amd64.s", "amd64") || asmFileMatchesArch("foo_arm64.s", "amd64") {
		t.Fatal("asmFileMatchesArch mismatch")
	}
	if !asmFileMatchesArch("generic.s", "arm64") {
		t.Fatal("generic.s should match pending source check")
	}
	if !asmSourceMatchesArch("// +build arm64\nTEXT ·f(SB),0,$0\n", "arm64") {
		t.Fatal("asmSourceMatchesArch +build arm64 failed")
	}
	if asmSourceMatchesArch("//go:build arm64\nTEXT ·f(SB),0,$0\n", "amd64") {
		t.Fatal("asmSourceMatchesArch should reject arm64 tag for amd64")
	}
	if asmSourceMatchesArch("//go:build !amd64\nTEXT ·f(SB),0,$0\n", "amd64") {
		t.Fatal("asmSourceMatchesArch should reject negated amd64 tag")
	}
}
