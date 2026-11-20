package sdkfrontend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestOwnedSDKReloadWorkspaceRejectsEqualMetadataReplacement(t *testing.T) {
	parent := t.TempDir()
	owned, release, err := newReloadWorkspace(parent)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	populate := func(directory string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, "retained.txt"), []byte("identical bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(directory, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	populate(owned)
	retained := owned + ".retained"
	// Deliberately do not call SameFile before replacement. Such a call fills
	// os.Lstat's lazy Windows file ID and conceals the old cleanup defect.
	if err := os.Rename(owned, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	populate(owned)
	if err := release(); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("equal-metadata replacement acquired the owned cleanup role: %v", err)
	}
	for _, directory := range []string{retained, owned} {
		actual, err := os.ReadFile(filepath.Join(directory, "retained.txt"))
		if err != nil || string(actual) != "identical bytes\n" {
			t.Fatalf("rejected cleanup removed original/replacement contents: %q: %v", directory, err)
		}
	}
}

func TestOwnedSDKReloadWorkspaceReleasesOnlyItsOwnDirectory(t *testing.T) {
	owned, release, err := newReloadWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "owned.txt"), []byte("owned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("owned workspace survived successful cleanup", err)
	}
	if err := release(); err != nil {
		t.Fatal("successful cleanup was not idempotent", err)
	}
}
