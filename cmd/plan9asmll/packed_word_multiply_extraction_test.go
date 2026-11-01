package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsPackedWordMultiplyTypedTable(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repo, "amd64_packed_word_multiply_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Isolate the typed dispatch map: an unrelated lowering switch cannot hide
	// an extraction regression after the old duplicate switch is removed.
	isolated := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolated, "amd64_packed_word_multiply_forms.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	names := []string{"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW", "VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW"}
	for _, arch := range []string{"amd64", "386"} {
		for _, root := range []string{isolated, repo} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				if _, exists := supported[name]; !exists {
					t.Fatalf("%s lost typed-table extraction for %s", arch, name)
				}
			}
			for _, nonOpcode := range []string{"M0", "PMULLW.BAD", "amd64PackedWordMultiplyLow", "x86PackedLogicalVEXOrEVEX"} {
				if _, exists := supported[nonOpcode]; exists {
					t.Fatalf("%s advertised non-opcode %s", arch, nonOpcode)
				}
			}
		}
	}
}
