//go:build windows

package sourcepath

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Lstat captures identity from an open handle. os.Lstat defers reading the
// Windows file ID until os.SameFile, which can then observe a replacement at
// the same path. OPEN_REPARSE_POINT preserves the final symlink's own identity.
func Lstat(name string) (info os.FileInfo, resultErr error) {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "lstat identity", Path: name, Err: err}
	}
	handle, err := windows.CreateFile(path, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "lstat identity", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), name)
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			info = nil
		}
	}()
	return file.Stat()
}
