package gooriginalsrc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalDependencyQueryOwnsSeparateMetadata(t *testing.T) {
	temporary := t.TempDir()
	ancestor := filepath.Join(temporary, "go.mod")
	const ancestorBytes = "module example.invalid/ancestor\ngo 1.20\n"
	if err := os.WriteFile(ancestor, []byte(ancestorBytes), 0600); err != nil {
		t.Fatal(err)
	}
	var directory string
	output, err := RunDependencyQuery(context.Background(), temporary, "example.invalid/legacy", "v1.2.3", func(dir string) ([]byte, error) {
		directory = dir
		data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil || dir == temporary || !strings.Contains(string(data), "require example.invalid/legacy v1.2.3\n") {
			return nil, fmt.Errorf("exact legacy dependency lacks an independently owned query: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("command-produced checksums\n"), 0600); err != nil {
			return nil, err
		}
		return []byte("actual query output"), nil
	})
	if err != nil || string(output) != "actual query output" {
		t.Fatal("dependency query did not retain its actual command", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatal("completed command left its owned metadata", err)
	}
	data, err := os.ReadFile(ancestor)
	if err != nil || string(data) != ancestorBytes {
		t.Fatal("query changed ancestor metadata", err)
	}
}

func TestOriginalDependencyQueryFailureAndForeignCleanup(t *testing.T) {
	for _, variant := range []string{"command failure", "foreign member", "redirected metadata", "changed pin", "replacement", "removed metadata"} {
		t.Run(variant, func(t *testing.T) {
			temporary := t.TempDir()
			var directory string
			commandFailure := errors.New("actual query failed")
			_, err := RunDependencyQuery(context.Background(), temporary, "example.invalid/legacy", "v1.2.3", func(dir string) ([]byte, error) {
				directory = dir
				switch variant {
				case "command failure":
					return nil, commandFailure
				case "foreign member":
					return nil, os.WriteFile(filepath.Join(dir, "foreign.txt"), []byte("preserve"), 0600)
				case "redirected metadata":
					return nil, os.Symlink(filepath.Join(temporary, "outside"), filepath.Join(dir, "go.sum"))
				case "removed metadata":
					return nil, os.Remove(filepath.Join(dir, "go.mod"))
				case "changed pin", "replacement":
					data := "module example.invalid/plan9asm-original-query\ngo 1.20\nrequire example.invalid/legacy v1.2.4\n"
					if variant == "replacement" {
						data = strings.ReplaceAll(data, "v1.2.4", "v1.2.3") + "replace example.invalid/legacy => ../foreign\n"
					}
					return nil, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(data), 0600)
				}
				return nil, nil
			})
			if err == nil || variant == "command failure" && !errors.Is(err, commandFailure) {
				t.Fatal("failed or foreign command became a successful query", err)
			}
			if variant == "foreign member" {
				if data, err := os.ReadFile(filepath.Join(directory, "foreign.txt")); err != nil || string(data) != "preserve" {
					t.Fatal("query cleanup removed a foreign member", err)
				}
			}
		})
	}
}
