package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsAccumulatorSignExtendTypedTable(t *testing.T) {
	const file = "amd64_accumulator_sign_extend_forms.go"
	source, err := os.ReadFile(filepath.Join("../..", file))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, contents := range map[string][]byte{
		file:           source,
		"translate.go": []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		ops, err := extractSupportedOps(directory, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"CBW", "CWDE", "CDQE", "CWD", "CDQ", "CQO"} {
			if _, found := ops[op]; !found {
				t.Fatal("isolated typed table lost an accumulator family member", arch, op)
			}
		}
	}
}
