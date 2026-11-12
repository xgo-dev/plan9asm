package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSupportedOpsCMOVTypedTable(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(repo, "amd64_cmov_forms.go"))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	if err := os.WriteFile(filepath.Join(isolated, "amd64_cmov_forms.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, root := range []string{isolated, repo} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, width := range []string{"W", "L", "Q"} {
				for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
					if _, present := supported["CMOV"+width+condition]; !present {
						t.Fatal("typed table lost actual source name", arch, width, condition)
					}
				}
			}
			for _, invalid := range []string{"CMOVLE", "CMOVLLE.Z", "CMOVBNE", "x86ConditionalMoveSpecs", "cmovlle"} {
				if _, present := supported[invalid]; present {
					t.Fatal("typed table advertised non-source spelling", invalid)
				}
			}
		}
	}
}
