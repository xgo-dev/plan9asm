//go:build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The live current-SDK observer intentionally has a current-Go schema. The
// portable object/listing test also executes with Go1.20 and never asks this
// decoder to reinterpret historical object/builtin evidence as current data.
func TestX86DirectTailCurrentGoPhysicalObjects(t *testing.T) {
	for _, target := range []struct{ arch, goos string }{
		{"amd64", "linux"}, {"amd64", "darwin"}, {"amd64", "windows"},
		{"386", "linux"}, {"386", "windows"},
	} {
		t.Run(target.goos+"/"+target.arch, func(t *testing.T) {
			fixture := x86DirectTailRuntimeSources(target.arch)
			data, root := x86DirectTailOriginalObject(t, target.arch, target.goos, fixture.assembly)
			builtin, err := os.ReadFile(filepath.Join(root, "src", "cmd", "internal", "goobj", "builtinlist.go"))
			if err != nil {
				t.Fatal(err)
			}
			records, err := gostaticstorage.ObserveX86AssemblyText(data, builtin, target.goos+"/"+target.arch)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 23 {
				t.Fatalf("original physical TEXT namespace lost records: %d", len(records))
			}
			for _, record := range records {
				if len(record.Code) == 0 {
					t.Fatal("missing original physical code", record.Name)
				}
			}
		})
	}
}
