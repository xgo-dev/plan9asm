package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDataGlobalAlignmentCompleteRegisteredLinkerRules(t *testing.T) {
	root := testGOROOT(t)
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, "src", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data, loader := read("cmd/link/internal/ld/data.go"), read("cmd/link/internal/loader/loader.go")
	for _, arch := range []string{"amd64", "x86"} {
		limits, dispatch := read("cmd/link/internal/"+arch+"/l.go"), read("cmd/link/internal/"+arch+"/obj.go")
		if err := verifyGoAssemblyDataAlignmentRule(data, loader, limits, dispatch); err != nil {
			t.Fatal("complete official linker rule", err)
		}
		for name, changed := range map[string][]byte{
			"lazy-zero-is-not-sixteen":       []byte(strings.Replace(string(loader), "abits == 0 {\n\t\treturn 0", "abits == 0 {\n\t\treturn 16", 1)),
			"changed-symbol-alignment-shift": []byte(strings.Replace(string(loader), "abits - 1", "abits", 1)),
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				if !errors.Is(verifyGoAssemblyDataAlignmentRule(data, changed, limits, dispatch), ErrProbeNeedsContext) {
					t.Fatal("changed complete loader rule accepted")
				}
			})
		}
		for name, changed := range map[string][]byte{
			"different-size-loop":        []byte(strings.Replace(string(data), "int64(align) > ssz", "int64(align) >= ssz", 1)),
			"different-minimum":          []byte(strings.Replace(string(data), "min := int32(thearch.Minalign)", "min := int32(16)", 1)),
			"dropped-recorded-alignment": []byte(strings.Replace(string(data), "ldr.SetSymAlign(s, align)", "ldr.SetSymAlign(s, 1)", 1)),
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				if !errors.Is(verifyGoAssemblyDataAlignmentRule(changed, loader, limits, dispatch), ErrProbeNeedsContext) {
					t.Fatal("changed complete linker rule accepted")
				}
			})
		}
		if !errors.Is(verifyGoAssemblyDataAlignmentRule(data, loader, []byte(strings.Replace(string(limits), "maxAlign  = 32", "maxAlign  = 16", 1)), dispatch), ErrProbeNeedsContext) {
			t.Fatal("changed maximum accepted")
		}
	}
}
