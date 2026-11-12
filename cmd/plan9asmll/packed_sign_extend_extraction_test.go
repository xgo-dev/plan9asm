package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsPackedSignExtendIsolatedTypedTable(t *testing.T) {
	const name = "amd64_packed_sign_extend_forms.go"
	source, err := os.ReadFile(filepath.Join("../..", name))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for file, contents := range map[string][]byte{name: source, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(isolated, file), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{isolated, "../.."} {
		for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"BW", "BD", "BQ", "WD", "WQ", "DQ"} {
				for _, prefix := range []string{"P", "VP"} {
					op := prefix + "MOVSX" + suffix
					_, found := supported[op]
					if found != (arch == "amd64" || arch == "386") {
						t.Fatal("complete signed widening membership lost its architecture boundary", root, arch, op, found)
					}
				}
			}
			for _, invalid := range []string{"VPMOVSXBW.Z", "VPMOVSXBD.BCST", "VPMOVSXWD.SAE", "x86PackedSignExtendSpecs"} {
				if _, found := supported[invalid]; found {
					t.Fatal("typed map advertised a suffix or Go identifier as an opcode", root, arch, invalid)
				}
			}
		}
	}
}
