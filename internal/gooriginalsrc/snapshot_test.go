package gooriginalsrc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type retainedSourceReader interface {
	ReadRetained(string) ([]byte, error)
}

func TestSnapshotReadRetainedFullEOF(t *testing.T) {
	for _, role := range []string{"unchanged", "tail byte", "grown metadata", "replacement", "symlink"} {
		t.Run(role, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(root, "go.mod")
			original := bytes.Repeat([]byte("module example.invalid/source\n"), 3000)
			if err := os.WriteFile(name, original, 0600); err != nil {
				t.Fatal(err)
			}
			snapshot := NewSnapshot()
			if err := snapshot.Retain(name); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			switch role {
			case "tail byte":
				changed := append([]byte(nil), original...)
				changed[len(changed)-1] ^= 1
				if err := os.WriteFile(name, changed, 0600); err != nil {
					t.Fatal(err)
				}
			case "grown metadata":
				if err := os.Truncate(name, fileByteLimit+1); err != nil {
					t.Fatal(err)
				}
				after, err := os.Lstat(name)
				if err != nil || !os.SameFile(before, after) || after.Size() <= fileByteLimit {
					t.Fatal("first-party retained metadata did not actually grow past the original bound", err)
				}
			case "replacement", "symlink":
				backup := filepath.Join(t.TempDir(), "original")
				if err := os.Rename(name, backup); err != nil {
					t.Fatal(err)
				}
				if role == "symlink" {
					if err := os.Symlink(backup, name); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(name, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			reader, ok := any(snapshot).(retainedSourceReader)
			if !ok {
				t.Fatal("retained metadata has no strict bounded physical read route")
			}
			actual, err := reader.ReadRetained(name)
			if role == "unchanged" {
				if err != nil || !bytes.Equal(actual, original) {
					t.Fatal("original complete metadata tail was not read through EOF", err)
				}
			} else if err == nil || actual != nil {
				t.Fatal("changed or over-bound retained metadata yielded bytes")
			}
		})
	}
}

func TestSnapshotRepeatedAtCountBounds(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "member")
	if err := os.WriteFile(name, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"file", "directory", "cache directory"} {
		t.Run(role, func(t *testing.T) {
			snapshot := NewSnapshot()
			var repeat, add func(string) error
			switch role {
			case "file":
				if err := snapshot.Retain(name); err != nil {
					t.Fatal(err)
				}
				for i := 1; i < fileLimit; i++ {
					snapshot.hashes[fmt.Sprintf("count-only-%d", i)] = ""
				}
				repeat, add = snapshot.Retain, snapshot.Retain
			case "directory":
				if err := snapshot.Directory(root, false); err != nil {
					t.Fatal(err)
				}
				for i := 1; i < directoryLimit; i++ {
					snapshot.directories[fmt.Sprintf("count-only-%d", i)] = nil
				}
				repeat = func(name string) error { return snapshot.Directory(name, false) }
				add = repeat
			case "cache directory":
				set := &OriginSet{directories: make(map[string]os.FileInfo)}
				if err := set.retainCacheDirectory(root); err != nil {
					t.Fatal(err)
				}
				for i := 1; i < directoryLimit; i++ {
					set.directories[fmt.Sprintf("count-only-%d", i)] = nil
				}
				repeat, add = set.retainCacheDirectory, set.retainCacheDirectory
			}
			existing := root
			if role == "file" {
				existing = name
			}
			if err := repeat(existing); err != nil {
				t.Fatal("re-observing an existing physical role consumed a new count slot", err)
			}
			extra := filepath.Join(root, "new-"+role)
			if role == "file" {
				if err := os.WriteFile(extra, []byte{2}, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(extra, 0700); err != nil {
				t.Fatal(err)
			}
			if err := add(extra); err == nil {
				t.Fatal("a new physical role escaped the original count bound")
			}
		})
	}
}

func TestSnapshotRejectsRelativeDirectory(t *testing.T) {
	if err := NewSnapshot().Directory(".", false); err == nil {
		t.Fatal("relative directory acquired an original physical source role")
	}
}

func TestSnapshotFullEOFAndPhysicalRoles(t *testing.T) {
	for _, role := range []string{"unchanged", "tail byte", "same bytes replacement", "symlink", "added member"} {
		t.Run(role, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(root, "source")
			bytes := make([]byte, 64<<10+227)
			for i := range bytes {
				bytes[i] = byte(i)
			}
			if err := os.WriteFile(name, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			snapshot := NewSnapshot()
			if err := snapshot.Directory(root, true); err != nil {
				t.Fatal(err)
			}
			if snapshot.View().Hashes[name] != fmt.Sprintf("%x", sha256.Sum256(bytes)) {
				t.Fatal("snapshot did not hash the complete original tail through EOF")
			}
			switch role {
			case "tail byte":
				bytes[len(bytes)-1] ^= 1
				if err := os.WriteFile(name, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			case "same bytes replacement", "symlink":
				backup := filepath.Join(t.TempDir(), "original")
				if err := os.Rename(name, backup); err != nil {
					t.Fatal(err)
				}
				if role == "symlink" {
					if err := os.Symlink(backup, name); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(name, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			case "added member":
				if err := os.WriteFile(filepath.Join(root, "ignored"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = snapshot.Verify()
			if role == "unchanged" && err != nil {
				t.Fatal(err)
			}
			if role != "unchanged" && err == nil {
				t.Fatal("changed physical source role was accepted")
			}
		})
	}
}

func TestSnapshotOriginalSharedBounds(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := NewSnapshot()
	bytes := make([]byte, fileByteLimit)
	for i := 0; i < totalByteLimit/fileByteLimit; i++ {
		name := filepath.Join(root, fmt.Sprintf("member-%d", i))
		if err := os.WriteFile(name, bytes, 0600); err != nil {
			t.Fatal(err)
		}
		if err := snapshot.Retain(name); err != nil {
			t.Fatal("existing graph-wide byte budget rejected its boundary", err)
		}
	}
	if snapshot.bytes != totalByteLimit {
		t.Fatal("graph-wide byte accounting is incomplete")
	}
	if err := snapshot.Verify(); err != nil {
		t.Fatal(err)
	}
	overflow := filepath.Join(root, "extra")
	if err := os.WriteFile(overflow, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Retain(overflow); err == nil {
		t.Fatal("another module/member acquired a fresh byte budget")
	}
}

func TestOriginSetInvalidRoles(t *testing.T) {
	for _, cache := range []string{"", ".", "relative/cache"} {
		if _, err := NewOriginSet(cache, "/nonexistent/tool"); err == nil {
			t.Fatal("nonabsolute or missing source/tool role was accepted")
		}
	}
	if err := (*Snapshot)(nil).Verify(); err == nil {
		t.Fatal("nil source snapshot was accepted")
	}
	if err := (*OriginSet)(nil).Verify(); err == nil {
		t.Fatal("nil exact-source guard was accepted")
	}
}
