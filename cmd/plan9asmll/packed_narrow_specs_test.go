package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractSupportedOpsFindsCompletePackedNarrowSpecTable(t *testing.T) {
	const name = "amd64_packed_narrow_forms.go"
	data, err := os.ReadFile(filepath.Join("../..", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for file, content := range map[string][]byte{
		name: data, "translate.go": []byte("package plan9asm\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, file), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	wanted := []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB",
		"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"}
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		packs := 0
		for opcode := range supported {
			if len(opcode) >= 4 && (opcode[:4] == "PACK" || len(opcode) >= 5 && opcode[:5] == "VPACK") {
				packs++
			}
		}
		if packs != len(wanted) {
			t.Fatalf("%s isolated pack specification advertised %d names: %v", arch, packs, supported)
		}
		for _, opcode := range wanted {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s typed packed-narrow extraction omitted %s", arch, opcode)
			}
		}
	}
}
