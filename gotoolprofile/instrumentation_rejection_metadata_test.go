package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstrumentationSourceRejectionMetadataLateIdentity(t *testing.T) {
	for _, change := range []string{"bytes", "same-byte final symlink", "same-byte directory redirect", "removed"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			original := filepath.Join(root, "module")
			if err := os.Mkdir(original, 0700); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(original, "go.mod")
			contents := []byte("module example.invalid/source-refusal\n\ngo 1.20\n")
			if err := os.WriteFile(name, contents, 0600); err != nil {
				t.Fatal(err)
			}
			physical, err := filepath.EvalSymlinks(name)
			if err != nil {
				t.Fatal(err)
			}
			metadata := instrumentationRejectedMetadata{path: name, physical: physical, digest: bytesSHA256(contents)}
			if err := metadata.verify(); err != nil {
				t.Fatal("original owned metadata: ", err)
			}
			switch change {
			case "bytes":
				if err := os.WriteFile(name, append(contents, []byte("// changed\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "same-byte final symlink":
				replacement := filepath.Join(root, "equal-bytes.mod")
				if err := os.Rename(name, replacement); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, name); err != nil {
					t.Fatal(err)
				}
			case "same-byte directory redirect":
				replacement := filepath.Join(root, "redirected-module")
				if err := os.Rename(original, replacement); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(replacement, original); err != nil {
					t.Fatal(err)
				}
			case "removed":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
			if err := metadata.verify(); err == nil {
				t.Fatal("late missing, changed or physically redirected metadata retained source credit")
			}
		})
	}
}
