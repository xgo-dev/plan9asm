package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteScalarBitFieldSpecTable(t *testing.T) {
	const filename = "amd64_scalar_bitfield_forms.go"
	data, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, filename), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(directory, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"BEXTRL", "BEXTRQ", "BZHIL", "BZHIQ"} {
			if _, present := supported[op]; !present {
				t.Error("complete scalar bit-field family lost its CLI opcode", arch, op)
			}
		}
	}
}
