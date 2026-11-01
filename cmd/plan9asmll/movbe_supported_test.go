package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteMOVBETable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_movbe_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "amd64_movbe_forms.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			if _, ok := supported[op]; !ok {
				t.Error("isolated complete MOVBE table omitted Go spelling", arch, op)
			}
		}
	}
}
