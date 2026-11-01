package sourcepath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveActualSourceAndMissingPaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "source.s")
	if err := os.WriteFile(file, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.s")
	if err := os.Symlink(file, alias); err != nil {
		t.Fatal(err)
	}
	resolved, err := Resolve(file)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := Resolve(alias); err != nil || actual != resolved {
		t.Fatalf("actual symlink identity differs: got=%q want=%q error=%v", actual, resolved, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{file, alias, filepath.Join(root, "missing", "child")} {
		if actual, err := Resolve(missing); actual != "" || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing/broken path was accepted or lost its cause: path=%q resolved=%q error=%v", missing, actual, err)
		}
	}
}
