package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteMOVNTITypedFamily(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_movnti_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string][]byte{
		"amd64_movnti_forms.go": data,
		"translate.go":          []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{dir, "../.."} {
		for _, arch := range []string{"386", "amd64"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"MOVNTIL", "MOVNTIQ"} {
				if _, found := supported[op]; !found {
					t.Fatal("complete scalar non-temporal family disappeared from reporting", arch, op)
				}
			}
		}
	}
}
