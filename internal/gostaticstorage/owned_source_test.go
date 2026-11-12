package gostaticstorage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedSourceDirectoryUsesPhysicalAncestors(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "Cache")
	child := filepath.Join(root, "module", "nested")
	sibling := filepath.Join(base, "Cache-other")
	for _, directory := range []string{child, sibling} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name, directory, root string
		inside                bool
	}{
		{"root itself", root, root, true},
		{"nested child", child, root, true},
		{"prefix sibling", sibling, root, false},
		{"case spelling", child, filepath.Join(base, strings.ToUpper(filepath.Base(root))), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "case spelling" {
				original, err := os.Stat(root)
				if err != nil {
					t.Fatal(err)
				}
				alternate, err := os.Stat(test.root)
				if os.IsNotExist(err) {
					if err := os.Mkdir(test.root, 0700); err != nil {
						t.Fatal(err)
					}
					alternate, err = os.Stat(test.root)
				}
				if err != nil {
					t.Fatal(err)
				}
				test.inside = os.SameFile(original, alternate)
			}
			inside, err := SourceDirectoryWithinRoot(test.directory, test.root)
			if err != nil || inside != test.inside {
				t.Fatalf("physical ancestor relationship: inside=%v, want=%v, error=%v", inside, test.inside, err)
			}
			if test.inside {
				if err := ValidateOwnedSourceDirectory(test.directory, sibling, test.root); !errors.Is(err, ErrContext) {
					t.Fatal("physical cached source acquired owned role", err)
				}
			}
		})
	}
}
