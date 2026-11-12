//go:build windows

package sourcepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Resolve uses the actual opened file identity, including directory junctions.
// Go 1.23 changed os.FileMode for junctions: EvalSymlinks may leave the alias
// unchanged or fail at a descendant. Neither result binds a physical source.
// This does not change process-wide GODEBUG settings or trust a lexical path
// merely because Stat succeeds. Callers still own containment and live guards.
func Resolve(name string) (resolved string, resultErr error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			resolved = ""
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 512)
	for len(buffer) <= 32768 {
		// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS, both zero. Unknown,
		// unavailable or inaccessible native routes are errors, not fallbacks.
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", &os.PathError{Op: "resolve final source path", Path: name, Err: err}
		}
		if n >= uint32(len(buffer)) {
			if n >= 32768 {
				break
			}
			buffer = make([]uint16, n+1)
			continue
		}
		resolved, err = windowsDOSPath(windows.UTF16ToString(buffer[:n]))
		if err != nil {
			return "", err
		}
		reopened, err := os.Stat(resolved)
		if err != nil {
			return "", err
		}
		if !os.SameFile(info, reopened) {
			return "", fmt.Errorf("resolved source path changed its opened file identity")
		}
		return resolved, nil
	}
	return "", fmt.Errorf("resolved source path exceeds the Windows UTF-16 path bound")
}

func windowsDOSPath(name string) (string, error) {
	switch {
	case strings.HasPrefix(name, `\\?\UNC\`):
		name = `\\` + strings.TrimPrefix(name, `\\?\UNC\`)
	case strings.HasPrefix(name, `\\?\`) && len(name) >= 7 && name[5:7] == `:\` &&
		(name[4] >= 'A' && name[4] <= 'Z' || name[4] >= 'a' && name[4] <= 'z'):
		name = name[4:]
	default:
		return "", fmt.Errorf("resolved source has no normalized Windows DOS or UNC path")
	}
	if !filepath.IsAbs(name) || strings.ContainsAny(name, "\x00\r\n") || filepath.Clean(name) != name {
		return "", fmt.Errorf("resolved source path is not canonical")
	}
	return name, nil
}
