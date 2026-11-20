package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteNonTemporalVectorSpec(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_nontemporal_vector_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, source := range map[string][]byte{
		"amd64_nontemporal_vector_forms.go": data,
		"translate.go":                      []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), source, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"MOVNTO", "MOVNTDQ", "MOVNTPD", "MOVNTPS", "MOVNTDQA",
			"VMOVNTDQ", "VMOVNTPD", "VMOVNTPS", "VMOVNTDQA",
		} {
			if _, found := supported[name]; !found {
				t.Fatal("complete typed non-temporal registry disappeared from opcode reporting", arch, name)
			}
		}
	}
}
