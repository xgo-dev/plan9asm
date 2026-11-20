package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteImplicitDivideTypedFamily(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_implicit_divide.go"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, contents := range map[string][]byte{
		"amd64_implicit_divide.go": data,
		"translate.go":             []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{directory, "../.."} {
		for _, arch := range []string{"386", "amd64"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"DIVB", "DIVW", "DIVL", "DIVQ", "IDIVB", "IDIVW", "IDIVL", "IDIVQ"} {
				if _, found := supported[op]; !found {
					t.Fatal("complete division family disappeared from opcode reporting", arch, op)
				}
			}
		}
	}
}
