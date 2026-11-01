package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsARM64ConditionalCompareSpec(t *testing.T) {
	const filename = "arm64_lower_float_conditional_compare.go"
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
		for _, arch := range []string{"arm64", "arm", "amd64", "386", "wasm"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED"} {
				_, present := supported[operation]
				if present != (arch == "arm64") {
					t.Errorf("%s extraction %s present=%t", arch, operation, present)
				}
			}
		}
	}
}
