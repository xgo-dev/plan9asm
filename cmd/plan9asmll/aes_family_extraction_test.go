package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompleteAESTypedFamily(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_aes_family_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "amd64_aes_family_forms.go"), data, 0600); err != nil {
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
		for _, name := range []string{"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST", "VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST", "VAESIMC", "VAESKEYGENASSIST"} {
			if _, known := supported[name]; !known {
				t.Fatal("typed AES registry extraction omitted", arch, name)
			}
		}
	}
}
