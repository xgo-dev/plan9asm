package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsCompleteConflictFunnelTypedFamilies(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		file  string
		names []string
	}{
		{file: "amd64_lower_conflict.go", names: []string{"VPCONFLICTD", "VPCONFLICTQ"}},
		{file: "amd64_lower_funnel_shift.go", names: []string{
			"VPSHLDW", "VPSHLDD", "VPSHLDQ", "VPSHLDVW", "VPSHLDVD", "VPSHLDVQ",
			"VPSHRDW", "VPSHRDD", "VPSHRDQ", "VPSHRDVW", "VPSHRDVD", "VPSHRDVQ",
		}},
	} {
		source, err := os.ReadFile(filepath.Join(repo, family.file))
		if err != nil {
			t.Fatal(err)
		}
		isolated := t.TempDir()
		if err := os.WriteFile(filepath.Join(isolated, family.file), source, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(isolated, "translate.go"), []byte("package plan9asm\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, arch := range []string{"386", "amd64"} {
			for _, root := range []string{isolated, repo} {
				supported, err := extractSupportedOps(root, arch)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range family.names {
					if _, present := supported[name]; !present {
						t.Fatal("complete typed family omitted a source name", arch, name)
					}
				}
				for _, invalid := range []string{"VPCONFLICT", "VPSHLD", "VPSHRD", "VPCONFLICTD.Z", "VPSHRDVQ.BCST", "amd64FunnelShiftSpecs"} {
					if _, present := supported[invalid]; present {
						t.Fatal("typed family extraction advertised a non-source spelling", arch, invalid)
					}
				}
			}
		}
	}
}
