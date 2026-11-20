package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSupportedOpsFindsCompletePackedMoveSpecTable(t *testing.T) {
	name := "amd64_packed_vector_move_forms.go"
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
	for _, arch := range []string{"amd64", "386"} {
		supported, err := extractSupportedOps(dir, arch)
		if err != nil {
			t.Fatal(err)
		}
		wanted := []string{
			"VMOVDQA", "VMOVDQU", "VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS",
			"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
		}
		moves := 0
		for opcode := range supported {
			if strings.HasPrefix(opcode, "VMOV") {
				moves++
			}
		}
		if moves != len(wanted) {
			t.Fatalf("%s packed-move-only map extraction: %v", arch, supported)
		}
		for _, opcode := range wanted {
			if _, present := supported[opcode]; !present {
				t.Errorf("%s typed packed-move extraction omitted %s", arch, opcode)
			}
		}
	}
}
