package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOrdinaryDependencyRootPathRoles(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "module")
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "pkg", "source.go")
	if err := os.WriteFile(file, []byte("package pkg\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	observed := filepath.Join(alias, "module")
	other := filepath.Join(t.TempDir(), "other-alias")
	if err := os.Symlink(root, other); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "pkg"), filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, filename, want string
	}{
		{"observed root", observed, root},
		{"canonical root", root, root},
		{"observed file", filepath.Join(observed, "pkg/source.go"), file},
		{"canonical file", file, file},
		{"other alias", filepath.Join(other, "pkg/source.go"), ""},
		{"internal alias", filepath.Join(observed, "redirect/source.go"), ""},
		{"missing", filepath.Join(observed, "missing.go"), ""},
		{"relative", "pkg/source.go", ""},
		{"unclean", observed + "/pkg/../pkg/source.go", ""},
		{"outside", filepath.Join(parent, "outside.go"), ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, spelling := range []struct {
				name, observed, root, file string
			}{
				{"native", observed, root, row.filename},
				{"module replacement slash", filepath.ToSlash(observed), root, row.filename},
				{"selected source slash", observed, root, filepath.ToSlash(row.filename)},
				{"all slash", filepath.ToSlash(observed), filepath.ToSlash(root), filepath.ToSlash(row.filename)},
			} {
				t.Run(spelling.name, func(t *testing.T) {
					got, err := ordinaryDependencyOriginalPath(spelling.observed, spelling.root, spelling.file)
					if row.want == "" {
						if err == nil || got != "" {
							t.Fatalf("unbound source path acquired ownership: %s", got)
						}
					} else if err != nil || got != row.want {
						t.Fatalf("same original root spelling: got %s; %v", got, err)
					}
				})
			}
		})
	}
}
