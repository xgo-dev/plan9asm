package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompletePackedPrecisionIsolatedSource(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	const name = "amd64_packed_precision_forms.go"
	source, err := os.ReadFile(filepath.Join(repo, name))
	if err != nil {
		t.Fatal(err)
	}
	isolated := t.TempDir()
	for file, content := range map[string][]byte{name: source, "translate.go": []byte("package plan9asm\n")} {
		if err := os.WriteFile(filepath.Join(isolated, file), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{isolated, repo} {
		for _, arch := range []string{"amd64", "386"} {
			supported, err := extractSupportedOps(root, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"CVTPS2PD", "CVTPD2PS", "VCVTPS2PD", "VCVTPD2PSX", "VCVTPD2PSY", "VCVTPD2PS"} {
				if _, found := supported[op]; !found {
					t.Fatal("isolated packed precision registry omitted an actual source name", arch, op)
				}
			}
			for _, invalid := range []string{"VCVTPS2PD.SAE", "VCVTPD2PS.BCST.Z", "x86PackedPrecisionSpecs"} {
				if _, found := supported[invalid]; found {
					t.Fatal("registry advertised a control or Go identifier as a source opcode", arch, invalid)
				}
			}
		}
	}
}
