package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsDwordProductTypedTable(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repo, "amd64_dword_product_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolated, "amd64_dword_product_forms.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, root := range []string{isolated, repo} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"PMULDQ", "PMULULQ", "VPMULDQ", "VPMULUDQ"} {
				if _, exists := supported[name]; !exists {
					t.Fatal("typed-table extraction omitted family member", arch, name)
				}
			}
			for _, name := range []string{"PMULUDQ", "PMULDQ.BAD", "pmuludq", "x86PackedLogicalVEXOrEVEX"} {
				if _, exists := supported[name]; exists {
					t.Fatal("typed table advertised non-source opcode", arch, name)
				}
			}
		}
	}
}
