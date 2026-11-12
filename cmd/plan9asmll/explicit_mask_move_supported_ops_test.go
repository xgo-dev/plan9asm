package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsIsolatedCompleteExplicitMaskMoveFamily(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../..", "amd64_explicit_mask_move_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "amd64_explicit_mask_move_forms.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386", "arm", "arm64", "wasm"} {
		supported, err := extractSupportedOps(directory, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, opcode := range []string{"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ"} {
			_, found := supported[opcode]
			if found != (arch == "amd64" || arch == "386") {
				t.Fatal("complete isolated vector-mask table lost its architecture boundary", arch, opcode, found)
			}
		}
	}
}
