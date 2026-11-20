package gostaticstorage

import (
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// SourceDirectoryWithinRoot is a physical relationship query, not a source
// permission. Existing ancestors must be compared by identity: case aliases
// can name the same directory even when EvalSymlinks preserves their spelling.
func SourceDirectoryWithinRoot(directory, root string) (bool, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(root) {
		return false, contextError("physical source relationship requires absolute roots")
	}
	physical, err := sourcepath.Resolve(directory)
	if err != nil {
		return false, err
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, err
	}
	if !rootInfo.IsDir() {
		return false, contextError("physical source root is not a directory")
	}
	for ancestor := physical; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Stat(ancestor)
		if err != nil {
			return false, err
		}
		if !info.IsDir() {
			return false, contextError("physical source ancestor is not a directory")
		}
		if os.SameFile(info, rootInfo) {
			return true, nil
		}
		if filepath.Dir(ancestor) == ancestor {
			return false, nil
		}
	}
}

// ValidateOwnedSourceDirectory excludes physical SDK and downloaded cache
// roots from the ordinary owned-main observation role. Go's Main/Version
// metadata alone cannot identify that role. This check grants no permission.
func ValidateOwnedSourceDirectory(directory, goRoot, moduleCache string) error {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(goRoot) || !filepath.IsAbs(moduleCache) {
		return contextError("owned source lacks actual absolute SDK/cache/source roots")
	}
	physicalDirectory, err := sourcepath.Resolve(directory)
	if err != nil {
		return err
	}
	if physicalDirectory != directory {
		return contextError("owned source directory is redirected")
	}
	for _, forbidden := range []string{goRoot, moduleCache} {
		inside, err := SourceDirectoryWithinRoot(physicalDirectory, forbidden)
		if err != nil {
			return err
		}
		if inside {
			return contextError("cached external or SDK source cannot acquire an ordinary owned-main role")
		}
	}
	return nil
}
