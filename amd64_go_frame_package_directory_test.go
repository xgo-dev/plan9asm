package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGoAMD64FrameSourceChildDirectoriesStayOutsidePackage(t *testing.T) {
	for _, change := range []string{"contents", "replacement", "regular file", "symlink", "removed", "new sibling", "source bytes"} {
		t.Run(change, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			child := filepath.Join(request.Directory, "testdata")
			if err := os.Mkdir(child, 0700); err != nil {
				t.Fatal(err)
			}
			unused := filepath.Join(child, "unused.bin")
			file, err := os.Create(unused)
			if err != nil {
				t.Fatal(err)
			}
			truncateErr := file.Truncate(17 << 20)
			if err := errors.Join(truncateErr, file.Close()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source := requireGoAMD64FrameCapture(t, pkg, request)
			if _, retained := source.inputs[unused]; retained {
				t.Fatal("unimported descendant became a package input")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "contents":
				err = os.WriteFile(unused, []byte("not a compiler input"), 0600)
			case "replacement", "regular file", "symlink", "removed":
				// Keep the old inode alive so replacement cannot reuse it.
				err = os.Rename(child, filepath.Join(t.TempDir(), "original"))
				if err == nil {
					switch change {
					case "replacement":
						err = os.Mkdir(child, 0700)
					case "regular file":
						err = os.WriteFile(child, []byte("changed role"), 0600)
					case "symlink":
						err = os.Symlink(t.TempDir(), child)
					}
				}
			case "new sibling":
				err = os.Mkdir(filepath.Join(request.Directory, "new"), 0700)
			case "source bytes":
				err = os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package changed\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = source.Verify(ctx)
			if change == "contents" {
				if err != nil {
					t.Fatalf("unimported contents changed the package witness: %v", err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed original input role remained valid: %v", err)
			}
		})
	}
}
