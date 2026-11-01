package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsARM64ScalarBinarySpec(t *testing.T) {
	const filename = "arm64_scalar_binary.go"
	source, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for name, contents := range map[string][]byte{filename: source, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(isolated, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{isolated, "../.."} {
		for _, arch := range []string{"arm64", "arm", "amd64", "386", "wasm"} {
			// Other architectures may legitimately own the same spelling in
			// their independent tables. Isolation proves this map cannot leak.
			if root == "../.." && arch != "arm64" {
				continue
			}
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"FADDS", "FADDD", "FSUBS", "FSUBD", "FMULS", "FMULD", "FNMULS", "FNMULD", "FDIVS", "FDIVD"} {
				_, present := supported[operation]
				if present != (arch == "arm64") {
					t.Errorf("%s %s extraction %s present=%t", root, arch, operation, present)
				}
			}
		}
	}
}
