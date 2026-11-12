package sourcepath

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLstatRetainsIdentityAfterReplacement(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			stamp := time.Unix(1700000000, 0)
			create := func() {
				t.Helper()
				var err error
				if directory {
					err = os.Mkdir(path, 0700)
				} else {
					err = os.WriteFile(path, []byte("identical bytes\n"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			create()
			before, err := Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			// Do not call SameFile before replacing: that would eagerly fill
			// os.Lstat's lazy ID and conceal the Windows regression.
			retained := path + ".retained"
			if err := os.Rename(path, retained); err != nil {
				t.Fatal(err)
			}
			create()
			replacement, err := Lstat(path)
			if err != nil || os.SameFile(before, replacement) {
				t.Fatalf("replacement inherited the reserved identity: %v", err)
			}
			original, err := Lstat(retained)
			if err != nil || !os.SameFile(before, original) {
				t.Fatalf("renamed original lost its captured identity: %v", err)
			}
		})
	}
}
