package gotoolprofile

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// SourceInventory is shared byte/membership evidence. Its capture and replay
// do not authorize any package, module, embed, test or instrumentation role.
type SourceInventory struct {
	Sources     map[string]string            `json:"sources"`
	Headers     map[string]string            `json:"selection_headers"`
	Directories map[string][]TestSourceEntry `json:"directories"`
}

// CaptureSourceDirectory retains every immediate member and every ancestor.
// Recursive capture is needed for an embed pattern's negative-selection proof;
// ordinary source-only packages need only their own directory and ancestors.
func CaptureSourceDirectory(ctx context.Context, inventory *SourceInventory, root, directory string, recursive bool) error {
	if ctx == nil || ctx.Err() != nil || inventory == nil {
		return fmt.Errorf("source inventory capture requires a live context")
	}
	resolved, err := sourcepath.Resolve(root)
	if err != nil || resolved != root || !filepath.IsAbs(root) {
		return fmt.Errorf("source inventory root is missing or redirected")
	}
	name, err := filepath.Rel(root, directory)
	name = filepath.ToSlash(name)
	if err != nil || name != "." && !testSourceLocalPath(name) {
		return fmt.Errorf("source inventory directory escapes its bound root")
	}
	resolved, err = sourcepath.Resolve(directory)
	if err != nil || resolved != directory {
		return fmt.Errorf("source inventory directory is redirected")
	}
	if inventory.Sources == nil && inventory.Headers == nil && inventory.Directories == nil {
		inventory.Sources = make(map[string]string)
		inventory.Headers = make(map[string]string)
		inventory.Directories = make(map[string][]TestSourceEntry)
	} else if inventory.Sources == nil || inventory.Headers == nil || inventory.Directories == nil {
		return fmt.Errorf("source inventory has a partially initialized projection")
	}
	if name != "." {
		if err := CaptureSourceDirectory(ctx, inventory, root, filepath.Dir(directory), false); err != nil {
			return err
		}
	}
	if _, captured := inventory.Directories[name]; !captured {
		if len(inventory.Directories) >= 4096 {
			return fmt.Errorf("source inventory exceeds its directory bound")
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		entryCount := len(entries)
		for _, previous := range inventory.Directories {
			entryCount += len(previous)
		}
		if entryCount > 65536 {
			return fmt.Errorf("source inventory exceeds its total member bound")
		}
		members := make([]TestSourceEntry, 0, len(entries))
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			member := TestSourceEntry{Name: entry.Name(), Kind: "directory"}
			if !entry.IsDir() {
				if !entry.Type().IsRegular() || len(inventory.Sources) >= 65536 {
					return fmt.Errorf("source inventory contains unbounded/nonregular bytes")
				}
				file := path.Join(name, entry.Name())
				filename, err := CPPRegularSource(root, file)
				if err != nil {
					return err
				}
				data, err := readTestDependencySource(filename)
				if err != nil {
					return err
				}
				member.Kind, member.SHA256 = "file", bytesSHA256(data)
				inventory.Sources[file] = member.SHA256
				if path.Ext(file) == ".go" || path.Ext(file) == ".s" {
					if len(inventory.Headers) >= 32768 {
						return fmt.Errorf("source inventory exceeds its header bound")
					}
					header, err := TestSelectionHeader(file, data)
					if err != nil {
						return err
					}
					inventory.Headers[file] = header
				}
			}
			members = append(members, member)
		}
		inventory.Directories[name] = members
	}
	if recursive {
		for _, entry := range inventory.Directories[name] {
			if entry.Kind == "directory" {
				if err := CaptureSourceDirectory(ctx, inventory, root, filepath.Join(directory, entry.Name), true); err != nil {
					return err
				}
			}
		}
	}
	return ctx.Err()
}
