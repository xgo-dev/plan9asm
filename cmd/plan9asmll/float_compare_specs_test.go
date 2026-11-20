package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteFloatingCompareSpec(t *testing.T) {
	filename := "amd64_float_compare_forms.go"
	source, err := os.ReadFile(filepath.Join("../..", filename))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, contents := range map[string][]byte{
		filename: source, "translate.go": []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	wanted := []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		comparisons := 0
		for opcode := range supported {
			if strings.HasPrefix(opcode, "CMP") || strings.HasPrefix(opcode, "VCMP") {
				comparisons++
			}
		}
		if comparisons != len(wanted) {
			t.Fatalf("%s complete compare-map extraction differs: %v", arch, supported)
		}
		for _, opcode := range wanted {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s missing typed comparison %s", arch, opcode)
			}
		}
	}
}
