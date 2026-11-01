package gooriginalsrc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

func TestOriginSetModuleLanguageDeclaration(t *testing.T) {
	for _, fixture := range []struct {
		name, metadata, declared string
		invalid                  bool
	}{
		{"implicit", "module example.invalid/zip-guard\n", "", false},
		{"explicit", "module example.invalid/zip-guard\ngo 1.20\n", "1.20", false},
		{"missing module", "go 1.20\n", "", true},
		{"malformed language", "module example.invalid/zip-guard\ngo wrong\n", "", true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			set, receipt, files := originalZIPConsistencyFixture(t)
			files["go.mod"] = []byte(fixture.metadata)
			for _, name := range []string{filepath.Join(receipt.Dir, "go.mod"), receipt.GoMod} {
				if err := os.WriteFile(name, files["go.mod"], 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeOriginalZIPFixture(t, receipt.Zip, receipt.Path+"@"+receipt.Version, files, "unchanged")
			var err error
			receipt.Sum, err = dirhash.HashZip(receipt.Zip, dirhash.Hash1)
			if err != nil {
				t.Fatal(err)
			}
			receipt.GoModSum, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(files["go.mod"])), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			observed, err := set.Observe(context.Background(), receipt.Path, receipt.Version, receipt)
			if fixture.invalid {
				if !errors.Is(err, ErrUnclosedModuleDeclaration) {
					t.Fatalf("invalid original metadata accepted: %v", err)
				}
				if err := set.Verify(); err == nil {
					t.Fatal("invalid language metadata did not revoke its observation")
				}
				return
			}
			if err != nil || observed.GoVersion != fixture.declared {
				t.Fatalf("literal language directive was lost: %q, %v", observed.GoVersion, err)
			}
			if err := set.Verify(); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(filepath.Join(receipt.Dir, "go.mod"))
			if err != nil || !bytes.Equal(actual, files["go.mod"]) {
				t.Fatal("observation rewrote the original language metadata", err)
			}
		})
	}
}

func TestSelectedGoVersionKeepsModuleRoles(t *testing.T) {
	for _, declared := range []string{"", "1.16", "1.20", "1.27.1"} {
		if got := SelectedGoVersion(declared, false); got != declared {
			t.Fatalf("dependency metadata changed from %q to %q", declared, got)
		}
		wanted := declared
		if wanted == "" {
			wanted = "1.16"
		}
		if got := SelectedGoVersion(declared, true); got != wanted {
			t.Fatalf("main metadata = %q, want %q", got, wanted)
		}
	}
}
