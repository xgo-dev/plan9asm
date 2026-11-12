package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsQwordPermuteIsolatedTypedTable(t *testing.T) {
	const name = "amd64_permute_qword_forms.go"
	data, err := os.ReadFile(filepath.Join("../..", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for file, contents := range map[string][]byte{name: data, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(dir, file), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, arch := range []string{"amd64", "386", "arm", "arm64", "wasm"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"VPERMQ", "VPERMPD"} {
			_, found := supported[op]
			if found != (arch == "amd64" || arch == "386") {
				t.Fatal("isolated typed qword-permute table lost its architecture boundary", arch, op, found)
			}
		}
		for _, invalid := range []string{"VPERMQ.Z", "VPERMPD.BCST", "x86QwordPermuteBits"} {
			if _, found := supported[invalid]; found {
				t.Fatal("typed table advertised a modifier or Go identifier as an opcode", arch, invalid)
			}
		}
	}
}
