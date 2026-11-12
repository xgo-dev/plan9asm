//go:build !windows

package sourcepath

import "os"

// Lstat captures file identity immediately, without following a final symlink.
// Unlike os.Lstat on Windows, its FileInfo never reopens the original path
// later when os.SameFile is called.
func Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}
