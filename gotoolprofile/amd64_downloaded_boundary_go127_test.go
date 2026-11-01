//go:build go1.27

package gotoolprofile

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAMD64DownloadedObservationCommandBoundaryForeignGuards(t *testing.T) {
	for _, role := range []string{"control", "foreign member", "same-inode bytes", "file replacement", "directory replacement"} {
		t.Run(role, func(t *testing.T) {
			request, path, version := amd64DownloadedObservationFixture(t, "fixed-local")
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			var marker, canary string
			var originalBytes []byte
			var originalInfo os.FileInfo
			changed := false
			run := func(ctx context.Context, dir string, env []string, binary string, args ...string) ([]byte, []byte, error) {
				data, diagnostic, err := RunBounded(ctx, dir, env, binary, args...)
				if err != nil || changed || len(args) < 2 || args[0] != "mod" || args[1] != "download" {
					return data, diagnostic, err
				}
				changed, marker = true, dir
				name := filepath.Join(marker, "go.mod")
				original, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				originalBytes = original
				originalInfo, err = os.Lstat(name)
				if err != nil {
					t.Fatal(err)
				}
				switch role {
				case "foreign member":
					canary = filepath.Join(marker, "foreign.txt")
					err = os.WriteFile(canary, []byte("foreign owner"), 0600)
				case "same-inode bytes":
					canary = name
					before, statErr := os.Lstat(name)
					if statErr != nil {
						t.Fatal(statErr)
					}
					err = os.WriteFile(name, append(original, '\n'), 0600)
					after, statErr := os.Lstat(name)
					if statErr != nil || !os.SameFile(before, after) {
						t.Fatal("marker mutation did not preserve inode", statErr)
					}
				case "file replacement":
					canary = name
					if err := os.Rename(name, filepath.Join(t.TempDir(), "original-marker")); err != nil {
						t.Fatal(err)
					}
					err = os.WriteFile(name, original, 0600)
				case "directory replacement":
					if err := os.Rename(marker, filepath.Join(t.TempDir(), "original-boundary")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(marker, 0700); err != nil {
						t.Fatal(err)
					}
					canary = filepath.Join(marker, "foreign.txt")
					err = os.WriteFile(canary, []byte("replacement owner"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				return data, diagnostic, nil
			}
			observed, err := CaptureAMD64DownloadedPackageObservation(ctx, AMD64DownloadedObservationRequest{
				Original: request, SourceModule: path, SourceVersion: version,
			}, run)
			if observed != nil {
				if closeErr := observed.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !changed {
				t.Fatal("actual command boundary was not reached")
			}
			if role == "control" {
				if err != nil || observed == nil {
					t.Fatal("actual unmodified original download control failed", err)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("control retained its own boundary", err)
				}
				return
			}
			if err == nil || observed != nil {
				t.Error("changed command boundary was accepted as an unchanged original observation", err)
			}
			if _, err := os.Stat(canary); err != nil {
				t.Error("download marker cleanup removed foreign bytes/member/identity", err)
			} else {
				// Every canary is created by this first-party test. Remove only
				// that exact known fixture file and its now-empty replacement.
				if err := os.Remove(canary); err != nil {
					t.Fatal(err)
				}
				if role == "foreign member" {
					// Remove only the test's unchanged original metadata, not an
					// arbitrary member left behind by the refused production cleanup.
					name := filepath.Join(marker, "go.mod")
					info, statErr := os.Lstat(name)
					data, readErr := os.ReadFile(name)
					if statErr != nil || readErr != nil || !os.SameFile(info, originalInfo) || !bytes.Equal(data, originalBytes) {
						t.Fatal("original fixture metadata changed", statErr, readErr)
					}
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
