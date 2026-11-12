package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteDuplicateMoveTypedFamily(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_duplicate_move_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, contents := range map[string][]byte{
		"amd64_duplicate_move_forms.go": data,
		"translate.go":                  []byte("package plan9asm\n"),
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
			for _, op := range []string{"MOVDDUP", "MOVSHDUP", "MOVSLDUP", "VMOVDDUP", "VMOVSHDUP", "VMOVSLDUP"} {
				if _, found := supported[op]; !found {
					t.Fatal("typed duplicate family disappeared from CLI reporting", arch, op)
				}
			}
		}
	}
}
