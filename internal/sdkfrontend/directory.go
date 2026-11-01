package sdkfrontend

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// WorkingDirectory fixes the actual load directory's opened physical spelling.
// Pair it with the physical GOROOT/cache environment before packages.Load:
// cmd/go's internal-import checks compare directory prefixes, not file IDs.
// This grants no package selection, source, frame or numerical permission.
func WorkingDirectory(directory string) (string, error) {
	if directory == "" {
		var err error
		directory, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("locate package-load working directory: %w", err)
		}
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("locate package-load working directory: %w", err)
	}
	physical, err := sourcepath.Resolve(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve package-load working directory: %w", err)
	}
	info, err := sourcepath.Lstat(physical)
	if err != nil {
		return "", fmt.Errorf("inspect package-load working directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("package-load working directory is not its actual directory")
	}
	return physical, nil
}
