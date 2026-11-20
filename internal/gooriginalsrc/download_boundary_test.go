package gooriginalsrc

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOriginalDownloadBoundaryFailureAndForeignGuards(t *testing.T) {
	for _, role := range []string{"closed FD", "same-inode bytes", "file replacement", "directory replacement", "foreign member"} {
		t.Run(role, func(t *testing.T) {
			boundary, err := NewDownloadBoundary(t.TempDir(), "original-download-", "example.invalid/command")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := boundary.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
			})
			if role == "closed FD" {
				if err := boundary.file.Close(); err != nil {
					t.Fatal(err)
				}
				err := boundary.Prepare()
				if !errors.Is(err, os.ErrClosed) {
					t.Fatal("actual closed-descriptor write failure was not retained", err)
				}
				t.Log("ACTUAL_CLOSED_FD_WRITE", err)
				if _, err := os.Lstat(boundary.directory); !os.IsNotExist(err) {
					t.Fatal("actual early write failure left its owned command boundary", err)
				}
				return
			}
			if err := boundary.Prepare(); err != nil {
				t.Fatal(err)
			}
			switch role {
			case "same-inode bytes":
				changed := append([]byte(nil), boundary.written...)
				changed[0] ^= 1
				if err := os.WriteFile(boundary.name, changed, 0600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(boundary.name)
				if err != nil || !os.SameFile(info, boundary.fileInfo) {
					t.Fatal("byte mutation did not keep original inode", err)
				}
				if !errors.Is(boundary.Close(), ErrDownloadBoundaryChanged) {
					t.Fatal("changed same-inode metadata was removed")
				}
				if data, err := os.ReadFile(boundary.name); err != nil || string(data) != string(changed) {
					t.Fatal("foreign byte mutation was not preserved", err)
				}
				if err := os.WriteFile(boundary.name, boundary.written, 0600); err != nil {
					t.Fatal(err)
				}
			case "file replacement":
				moved := filepath.Join(t.TempDir(), "original-metadata")
				if err := os.Rename(boundary.name, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(boundary.name, boundary.written, 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(boundary.Close(), ErrDownloadBoundaryChanged) {
					t.Fatal("same-byte replacement metadata was removed")
				}
				if _, err := os.Stat(boundary.name); err != nil {
					t.Fatal("replacement metadata was not preserved", err)
				}
				if err := os.Remove(boundary.name); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(moved, boundary.name); err != nil {
					t.Fatal(err)
				}
			case "directory replacement":
				moved := filepath.Join(t.TempDir(), "original-boundary")
				if err := os.Rename(boundary.directory, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(boundary.directory, 0700); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(boundary.Close(), ErrDownloadBoundaryChanged) {
					t.Fatal("foreign replacement directory was removed")
				}
				if err := os.Remove(boundary.directory); err != nil {
					t.Fatal("replacement directory was not preserved", err)
				}
				if err := os.Rename(moved, boundary.directory); err != nil {
					t.Fatal(err)
				}
			case "foreign member":
				foreign := filepath.Join(boundary.directory, "foreign.txt")
				if err := os.WriteFile(foreign, []byte("foreign owner"), 0600); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(boundary.Close(), ErrDownloadBoundaryChanged) {
					t.Fatal("unexpected member did not invalidate cleanup")
				}
				if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign owner" {
					t.Fatal("foreign member was not preserved", err)
				}
				if err := os.Remove(foreign); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestOriginalDownloadBoundaryOwnerAndUnpreparedCleanup(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty original", true: "prepared original"}[prepared], func(t *testing.T) {
			boundary, err := NewDownloadBoundary(t.TempDir(), "original-download-", "example.invalid/command")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := boundary.Close(); err != nil {
					t.Error(err)
				}
			})
			if prepared {
				if err := boundary.Prepare(); err != nil {
					t.Fatal(err)
				}
			}
			copied := new(DownloadBoundary)
			reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(boundary).Elem())
			if copied.Directory() != "" || !errors.Is(copied.Verify(), ErrDownloadBoundaryChanged) ||
				!errors.Is(copied.Prepare(), ErrDownloadBoundaryChanged) || !errors.Is(copied.Close(), ErrDownloadBoundaryChanged) {
				t.Fatal("whole-value IO owner copy borrowed cleanup identity")
			}
			if _, err := os.Lstat(boundary.name); err != nil {
				t.Fatal("copied IO owner removed original metadata", err)
			}
			if err := boundary.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(boundary.directory); !os.IsNotExist(err) {
				t.Fatal("original empty/prepared boundary cleanup failed", err)
			}
		})
	}
}

func TestOriginalDownloadBoundaryRejectsRelativeTemporary(t *testing.T) {
	// An existing relative directory must fail before creating anything. Do
	// not require the checkout and testing's temporary root to share a volume.
	boundary, err := NewDownloadBoundary(".", "original-download-", "example.invalid/command")
	if boundary != nil {
		// Even a regressed implementation owns only its newly created child.
		defer func() {
			if err := boundary.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if err == nil || boundary != nil {
		t.Fatal("relative temporary directory acquired a command boundary", err)
	}
}
