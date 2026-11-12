package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsSignedPackedIntegerFloat(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_signed_packed_integer_float.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "amd64_signed_packed_integer_float.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		ops, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"} {
			if _, present := ops[name]; !present {
				t.Fatal(arch, "missing", name)
			}
		}
	}
}
