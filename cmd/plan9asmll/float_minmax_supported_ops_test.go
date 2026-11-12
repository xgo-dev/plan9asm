package main

import (
	"os"
	"path/filepath"
	"testing"
)

func testFloatArithmeticOpcodeExtraction(t *testing.T, opcodes []string) {
	t.Helper()
	const filename = "amd64_float_arithmetic_forms.go"
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, filename))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct{ name, root string }{
		{"isolated", dir}, {"repository", repoRoot},
	} {
		architectures := []string{"amd64", "386"}
		if source.name == "isolated" {
			// ARM also names an instruction MULSD. Check catalog exclusion
			// in isolation, and retain both complete-repository x86 controls.
			architectures = append(architectures, "arm", "arm64", "wasm")
		}
		for _, arch := range architectures {
			t.Run(source.name+"/"+arch, func(t *testing.T) {
				supported, err := extractSupportedOps(source.root, arch)
				if err != nil {
					t.Fatal(err)
				}
				for _, op := range opcodes {
					_, found := supported[op]
					if found != (arch == "amd64" || arch == "386") {
						t.Errorf("arithmetic catalog extraction changed its architecture boundary: %s %s found=%v", arch, op, found)
					}
				}
			})
		}
	}
}

func TestExtractSupportedOpsFindsIsolatedCompleteFloatMinMaxFamily(t *testing.T) {
	testFloatArithmeticOpcodeExtraction(t, []string{
		"MINPS", "MINPD", "MINSS", "MINSD", "MAXPS", "MAXPD", "MAXSS", "MAXSD",
		"VMINPS", "VMINPD", "VMINSS", "VMINSD", "VMAXPS", "VMAXPD", "VMAXSS", "VMAXSD",
	})
}
