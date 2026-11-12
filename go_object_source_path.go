package plan9asm

import (
	"path/filepath"
	"strings"
)

// originalGoObjectSourcePath decodes spelling only. Callers must separately
// bind this path to their captured physical source and exact original bytes.
// objabi.AbsFile emits forward slashes on Windows, including $GOROOT names.
func originalGoObjectSourcePath(name, root string) (string, bool) {
	if strings.HasPrefix(name, "$GOROOT/") {
		tail := strings.TrimPrefix(name, "$GOROOT/")
		native := filepath.FromSlash(tail)
		// Check the metadata before Join can erase dot segments or repeated
		// separators. An SDK prefix must not give aliases source authority.
		if !filepath.IsLocal(native) || filepath.ToSlash(filepath.Clean(native)) != tail {
			return "", false
		}
		name = filepath.Join(root, native)
	}
	name = filepath.FromSlash(name)
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return "", false
	}
	return name, true
}
