//go:build go1.27

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompileOneX86SDKGCFilterMaskWidthExistingObjects(t *testing.T) {
	const packagePath = "internal/runtime/gc/scan"
	const name = "filter_amd64.s"
	path := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(packagePath), name)
	before, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(before), "KMOVW K1, R15") ||
		!strings.Contains(string(before), "POPCNTL R15, R15") {
		t.Fatal("complete current-Go mask-word/popcount counterexample is absent", err)
	}
	t.Logf("complete original SDK GC filter source SHA256=%x", sha256.Sum256(before))
	compileX86SDKExistingObject(t, packagePath, name)
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(before) {
		t.Fatal("complete original SDK GC filter changed during compilation", err)
	}
}
