package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSupportedOpsFindsCompleteSqrtSpec(t *testing.T) {
	filename := "amd64_sqrt_forms.go"
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
	wanted := []string{"SQRTSS", "SQRTSD", "SQRTPS", "SQRTPD", "VSQRTSS", "VSQRTSD", "VSQRTPS", "VSQRTPD"}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		// Every extraction also includes generic assembler directives. Count
		// the complete family independently, then check each expected member.
		family := 0
		for opcode := range supported {
			if strings.HasPrefix(opcode, "SQRT") || strings.HasPrefix(opcode, "VSQRT") {
				family++
			}
		}
		if family != len(wanted) {
			t.Fatalf("%s complete sqrt-map extraction differs: %v", arch, supported)
		}
		for _, opcode := range wanted {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s missing typed sqrt %s", arch, opcode)
			}
		}
	}
}
