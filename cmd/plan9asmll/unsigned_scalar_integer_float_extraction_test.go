package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompleteUnsignedScalarIntegerFloatIsolatedSource(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const name = "amd64_lower_scalar_integer_float.go"
	source, err := os.ReadFile(filepath.Join(repo, name))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for file, data := range map[string][]byte{name: source, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(isolated, file), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{isolated, repo} {
		for _, arch := range []string{"amd64", "386"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"VCVTUSI2SDL", "VCVTUSI2SDQ", "VCVTUSI2SSL", "VCVTUSI2SSQ"} {
				if _, present := supported[op]; !present {
					t.Fatal("isolated scalar conversion registry omitted a complete unsigned member", arch, op)
				}
			}
			for _, invalid := range []string{"VCVTUSI2SDL.RN_SAE", "VCVTUSI2SSL.Z", "VCVTUSI2SSQ.BCST", "amd64ScalarIntegerFloatOps"} {
				if _, present := supported[invalid]; present {
					t.Fatal("unsigned registry advertised a control or Go identifier as an opcode", arch, invalid)
				}
			}
		}
	}
}
