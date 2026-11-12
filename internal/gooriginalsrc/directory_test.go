package gooriginalsrc

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestSnapshotNonrecursiveGraphMemberBounds(t *testing.T) {
	for _, role := range []string{"files across directories", "directory members"} {
		t.Run(role, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			snapshot := NewSnapshot()
			if role == "directory members" {
				for i := 0; i < directoryLimit; i++ {
					if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("directory-%04d", i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := snapshot.Directory(root, false); err == nil {
					t.Fatal("nonrecursive original directory members acquired a fresh graph-wide count budget")
				}
				return
			}
			for _, part := range []string{"first", "second"} {
				directory := filepath.Join(root, part)
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < fileLimit/2+1; i++ {
					file, err := os.OpenFile(filepath.Join(directory, fmt.Sprintf("member-%05d", i)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
					if err != nil {
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := snapshot.Directory(directory, false); part == "first" {
					if err != nil {
						t.Fatal("actual first bounded inventory was rejected", err)
					}
				} else if err == nil {
					t.Fatal("nonrecursive original file members acquired a fresh graph-wide count budget")
				}
			}
		})
	}
}

func TestOriginalDirectoryBoundedEOF(t *testing.T) {
	for _, maximum := range []int{0, 1, 256} {
		t.Run(fmt.Sprintf("bound-%d", maximum), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for i := maximum - 1; i >= 0; i-- {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("member-%03d", i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			entries, info, err := ReadDirectory(root, maximum)
			if err != nil || info == nil || len(entries) != maximum {
				t.Fatal("complete directory did not close its actual boundary EOF", err)
			}
			names := make([]string, len(entries))
			for i, entry := range entries {
				names[i] = entry.Name()
			}
			if !sort.StringsAreSorted(names) {
				t.Fatal("bounded original inventory changed the stable sorted member rule")
			}
			if err := os.WriteFile(filepath.Join(root, "overflow"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if entries, _, err := ReadDirectory(root, maximum); err == nil || entries != nil {
				t.Fatal("a truncated bounded directory prefix was accepted as complete")
			}
		})
	}
	for _, name := range []string{"", ".", "relative/directory"} {
		if _, _, err := ReadDirectory(name, 1); err == nil {
			t.Fatal("directory reader accepted a relative physical role")
		}
	}
}
