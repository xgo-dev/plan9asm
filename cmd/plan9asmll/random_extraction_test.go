package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteHardwareRandomSpecTable(t *testing.T) {
	const filename = "amd64_random_forms.go"
	source, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, data := range map[string][]byte{
		filename:       source,
		"translate.go": []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		supported, err := extractSupportedOps(directory, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"RDRANDW", "RDRANDL", "RDRANDQ", "RDSEEDW", "RDSEEDL", "RDSEEDQ"} {
			_, present := supported[op]
			if present != (arch == "386" || arch == "amd64") {
				t.Error("complete hardware-random inventory changed", arch, op, present)
			}
		}
	}
}
