package plan9asm

import (
	"path/filepath"
	"testing"
)

func TestOriginalGoObjectSourcePathSpelling(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "source.s")
	for _, spelling := range []string{file, filepath.ToSlash(file)} {
		if actual, ok := originalGoObjectSourcePath(spelling, ""); !ok || actual != file {
			t.Fatalf("actual Go object spelling %q: got %q, valid %v", spelling, actual, ok)
		}
	}
	for _, spelling := range []string{
		"source.s", "$GOROOT/source.s", file + "/../source.s",
		filepath.ToSlash(root) + "//source.s", filepath.ToSlash(root) + "/./source.s",
	} {
		if actual, ok := originalGoObjectSourcePath(spelling, ""); ok {
			t.Fatalf("noncanonical object spelling %q accepted as %q", spelling, actual)
		}
	}
}
