package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompletePackedMultiplyAddSpecTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_maddword_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string][]byte{
		"amd64_maddword_forms.go": data,
		"translate.go":            []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, opcode := range []string{"PMADDWL", "PMADDUBSW", "VPMADDWD", "VPMADDUBSW"} {
			if _, exists := supported[opcode]; !exists {
				t.Fatalf("%s complete packed multiply-add extraction omitted %s", arch, opcode)
			}
		}
	}
}
