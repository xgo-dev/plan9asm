package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompleteQwordLookupTypedFamily(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repo, "amd64_lower_qword_bit_lookup.go"))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolated, "amd64_lower_qword_bit_lookup.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, root := range []string{isolated, repo} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"VPMULTISHIFTQB", "VPSHUFBITQMB"} {
				if _, present := supported[name]; !present {
					t.Fatal("complete typed qword lookup registry omitted a source name", arch, name)
				}
			}
			for _, invalid := range []string{"VPMULTISHIFTQB.Z", "VPSHUFBITQMB.BCST", "amd64QwordBitLookupSpecs"} {
				if _, present := supported[invalid]; present {
					t.Fatal("qword lookup extraction advertised a non-source spelling", arch, invalid)
				}
			}
		}
	}
}
