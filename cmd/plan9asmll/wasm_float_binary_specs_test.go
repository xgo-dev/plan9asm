package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteWasmFloatBinarySpec(t *testing.T) {
	const filename = "wasm_float_binary.go"
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
			count := 0
			for _, width := range []string{"F32", "F64"} {
				for _, operation := range []string{"EQ", "NE", "LT", "GT", "LE", "GE", "MIN", "MAX"} {
					name := width + operation
					_, present := supported[name]
					if present != (arch == "wasm") {
						t.Errorf("%s extraction %s present=%v; architecture-specific map consumer changed", arch, name, present)
					}
					count++
				}
			}
			if count != 16 {
				t.Fatal("complete Wasm comparison/minmax inventory changed", count)
			}
		}
	}
}
