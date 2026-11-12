package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteOrderingHintSpecTable(t *testing.T) {
	const name = "amd64_ordering_hint_forms.go"
	data, err := os.ReadFile(filepath.Join("../..", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		baseline, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		supported, err := extractSupportedOps(dir, arch)
		if err != nil || len(supported) != len(baseline)+4 {
			t.Fatalf("%s complete pure ordering/hint extraction: %v/%v", arch, supported, err)
		}
		for _, opcode := range []string{"LFENCE", "MFENCE", "SFENCE", "PAUSE"} {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s typed ordering/hint extraction omitted %s", arch, opcode)
			}
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}
