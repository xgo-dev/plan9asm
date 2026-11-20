package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompleteScalarPrecisionTypedFamily(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "amd64_scalar_precision_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolated, "amd64_scalar_precision_forms.go"), data, 0600); err != nil {
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
			for _, name := range []string{"CVTSS2SD", "CVTSD2SS", "VCVTSS2SD", "VCVTSD2SS"} {
				if _, present := supported[name]; !present {
					t.Fatal("complete typed precision registry omitted a source name", arch, name, root)
				}
			}
			for _, invalid := range []string{"CVTSS2SS", "CVTSD2SD", "VCVTSS2SD.SAE", "VCVTSD2SS.RN_SAE", "x86ScalarPrecisionSpecs"} {
				if _, present := supported[invalid]; present {
					t.Fatal("typed precision registry advertised a non-source spelling", arch, invalid, root)
				}
			}
		}
	}
}
