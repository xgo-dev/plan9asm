package plan9asm

import (
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

func TestGoAMD64DownloadedPackageIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "archive.example", "mirror@v1.0.0")
	original := gooriginalsrc.Module{Root: root, ModulePath: "example.invalid/declared"}
	for _, test := range []struct {
		name, directory, want string
	}{
		{"root alias", root, "example.invalid/declared"},
		{"nested alias", filepath.Join(root, "internal", "kernel"), "example.invalid/declared/internal/kernel"},
		{"parent", filepath.Dir(root), ""},
		{"prefix sibling", root + "-other", ""},
		{"traversal", filepath.Join(root, "..", "other"), ""},
		{"relative", "internal/kernel", ""},
		{"invalid import", filepath.Join(root, "bad path"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := goAMD64DownloadedPackagePath(original, test.directory)
			if test.want == "" {
				if err == nil || got != "" {
					t.Fatalf("unbound path acquired an original package identity: %q, %v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("original declared package = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}
