package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsNamedARM64MoveWideAndBitfield(t *testing.T) {
	const filename = "arm64_named_gp_fields.go"
	data, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for name, contents := range map[string][]byte{filename: data, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{directory, "../.."} {
		for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"MOVZ", "MOVZW", "MOVN", "MOVNW", "BFM", "BFMW", "SBFM", "SBFMW", "UBFM", "UBFMW"} {
				if _, found := supported[op]; found != (arch == "arm64") {
					t.Error("named family lost its architecture-scoped opcode", root, arch, op, found)
				}
			}
		}
	}
}
