package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func openDiscoveryReport(name string) (*os.File, error) {
	var file *os.File
	err := retryDiscoveryFileOperation(func() error {
		var err error
		file, err = openWindowsDiscoveryReport(name)
		return err
	}, func(err error) bool {
		// A missing report normally means the shard has not published yet.
		return !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) && transientDiscoveryFileError(err)
	}, time.Now, time.Sleep)
	return file, err
}

func openWindowsDiscoveryReport(name string) (*os.File, error) {
	path, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	// Preserve long-path support while allowing an atomic publisher to replace
	// the pathname. The open handle continues to read the previous complete file.
	if !strings.HasPrefix(path, `\\?\`) {
		if strings.HasPrefix(path, `\\`) {
			path = `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
		} else {
			path = `\\?\` + path
		}
	}
	encoded, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	// os.Open uses only FILE_SHARE_READ | FILE_SHARE_WRITE, which prevents
	// Windows from renaming over the report while a progress reader has it open.
	sharing := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	handle, err := syscall.CreateFile(encoded, syscall.GENERIC_READ, sharing, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(handle), name), nil
}

func publishDiscoveryReport(oldName, newName string) error {
	// As in Go's cmd/internal/robustio, sharing/deletion can remain pending
	// briefly after a handle closes. Never truncate/remove the previous report
	// to work around a failed rename: preserve it and return a terminal error.
	return retryDiscoveryFileOperation(func() error {
		return os.Rename(oldName, newName)
	}, transientDiscoveryFileError, time.Now, time.Sleep)
}

func transientDiscoveryFileError(err error) bool {
	var code syscall.Errno
	if !errors.As(err, &code) {
		return false
	}
	const sharingViolation syscall.Errno = 32
	return code == syscall.ERROR_ACCESS_DENIED || code == syscall.ERROR_FILE_NOT_FOUND || code == sharingViolation
}
