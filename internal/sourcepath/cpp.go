package sourcepath

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// CPPLocalSource describes a canonical slash-separated source name. It grants
// no source, tool or include authority to the path or its physical contents.
func CPPLocalSource(file string) bool {
	return file != "" && file != "." && !path.IsAbs(file) && path.Clean(file) == file &&
		file != ".." && !strings.HasPrefix(file, "../") && !strings.ContainsAny(file, ":\\\x00\r\n")
}

// CPPRegularSource binds a bounded canonical file within an actual origin.
// Parent/file symlinks cannot redirect a selected SDK or module include.
func CPPRegularSource(root, file string) (string, error) {
	if !filepath.IsAbs(root) || !CPPLocalSource(file) {
		return "", fmt.Errorf("unsafe exact CPP source identity")
	}
	resolvedRoot, err := Resolve(root)
	if err != nil {
		return "", err
	}
	name := filepath.Join(resolvedRoot, filepath.FromSlash(file))
	resolved, err := Resolve(name)
	if err != nil {
		return "", fmt.Errorf("CPP source is missing: %s: %w", file, err)
	}
	if resolved != name {
		return "", fmt.Errorf("CPP source is redirected: %s", file)
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", fmt.Errorf("CPP source must be a bounded regular file: %s", file)
	}
	return name, nil
}
