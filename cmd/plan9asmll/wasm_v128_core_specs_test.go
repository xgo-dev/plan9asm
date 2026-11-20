package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteWasmV128CoreSpec(t *testing.T) {
	const filename = "wasm_v128_core.go"
	source, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for name, contents := range map[string][]byte{
		filename: source, "translate.go": []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(isolated, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{isolated, "../.."} {
		for _, arch := range []string{"wasm", "386", "amd64", "arm", "arm64"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"V128CONST", "V128NOT", "V128AND", "V128ANDNOT", "V128OR", "V128XOR", "V128BITSELECT", "V128ANYTRUE"} {
				_, present := supported[name]
				if present != (arch == "wasm") {
					t.Errorf("%s extraction %s present=%t; V128 core escaped its architecture", arch, name, present)
				}
			}
		}
	}
}
