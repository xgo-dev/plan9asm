package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSupportedOpsFindsCompletePackedZeroExtendSpec(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_packed_zero_extend_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "amd64_packed_zero_extend_forms.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		familyCount := 0
		for name := range supported {
			if strings.HasPrefix(name, "PMOVZX") || strings.HasPrefix(name, "VPMOVZX") {
				familyCount++
			}
		}
		if familyCount != 12 {
			t.Fatalf("%s packed unsigned spec has %d family names, want exact 12", arch, familyCount)
		}
		for _, suffix := range []string{"BW", "BD", "BQ", "WD", "WQ", "DQ"} {
			for _, prefix := range []string{"P", "VP"} {
				if _, exists := supported[prefix+"MOVZX"+suffix]; !exists {
					t.Fatalf("%s extraction omitted %sMOVZX%s", arch, prefix, suffix)
				}
			}
		}
	}
}
