package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteCOMISpec(t *testing.T) {
	filename := "amd64_comi_forms.go"
	source, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string][]byte{
		filename: source, "translate.go": []byte("package plan9asm\n"),
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
		for _, opcode := range []string{"COMISS", "COMISD", "UCOMISS", "UCOMISD", "VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s missing scalar flag comparison %s", arch, opcode)
			}
		}
	}
}
