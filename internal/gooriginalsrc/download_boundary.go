package gooriginalsrc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
)

// ErrDownloadBoundaryChanged rejects cleanup of foreign bytes or identities.
var ErrDownloadBoundaryChanged = errors.New("download command boundary changed")

// DownloadBoundary owns temporary command IO, not source or frame authority.
// It removes only its original metadata file and then its empty directory.
type DownloadBoundary struct {
	mu                      sync.Mutex
	identity                *DownloadBoundary
	directory, name         string
	directoryInfo, fileInfo os.FileInfo
	file                    *os.File
	metadata                string
	written                 []byte
	prepared                bool
	fileClosed, fileRemoved bool
	directoryRemoved        bool
	closeErr                error
}

// NewDownloadBoundary gives a download command an independent module boundary
// so that it cannot mutate an ancestor module. All IO uses actual OS primitives.
func NewDownloadBoundary(temporary, prefix, modulePath string) (_ *DownloadBoundary, result error) {
	if temporary != "" && !filepath.IsAbs(temporary) ||
		prefix == "" || len(prefix) > 255 || strings.ContainsAny(prefix, "/\\\x00") ||
		module.CheckPath(modulePath) != nil || len(modulePath) > fileByteLimit-32 {
		return nil, fmt.Errorf("invalid bounded download command boundary")
	}
	created, err := os.MkdirTemp(temporary, prefix)
	if err != nil {
		return nil, err
	}
	boundary := &DownloadBoundary{directory: created, metadata: "module " + modulePath + "\ngo 1.20\n"}
	boundary.identity = boundary
	boundary.directoryInfo, err = os.Lstat(created)
	if err != nil || !boundary.directoryInfo.IsDir() {
		// Without a stable directory identity there is no safe cleanup target.
		return nil, errors.Join(ErrDownloadBoundaryChanged, err)
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, boundary.Close())
		}
	}()
	physical, err := sourcepath.Resolve(created)
	if err != nil {
		return nil, err
	}
	boundary.directory = physical
	entries, info, err := ReadDirectory(physical, 0)
	if err != nil || len(entries) != 0 || !os.SameFile(boundary.directoryInfo, info) {
		return nil, errors.Join(ErrDownloadBoundaryChanged, err)
	}
	boundary.name = filepath.Join(physical, "go.mod")
	boundary.file, err = os.OpenFile(boundary.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	boundary.fileInfo, err = boundary.file.Stat()
	if err != nil {
		return nil, err
	}
	return boundary, nil
}

func (boundary *DownloadBoundary) ownsIdentity() bool {
	return boundary != nil && boundary.identity == boundary
}

// Directory exposes only a command working directory, never a source role.
func (boundary *DownloadBoundary) Directory() string {
	if !boundary.ownsIdentity() {
		return ""
	}
	return boundary.directory
}

// Prepare writes and closes the actual descriptor. A failed or partial write
// retains its cause and cleans up only the bytes that were actually written.
func (boundary *DownloadBoundary) Prepare() (result error) {
	if !boundary.ownsIdentity() {
		return ErrDownloadBoundaryChanged
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	if boundary.prepared || boundary.fileClosed || boundary.directoryRemoved {
		return errors.Join(ErrDownloadBoundaryChanged, boundary.closeErr)
	}
	boundary.prepared = true
	defer func() {
		if result != nil {
			result = errors.Join(result, boundary.close())
		}
	}()
	n, err := boundary.file.WriteString(boundary.metadata)
	boundary.written = []byte(boundary.metadata[:n])
	if err := errors.Join(err, boundary.closeFile()); err != nil {
		return err
	}
	return boundary.verify()
}

func (boundary *DownloadBoundary) closeFile() error {
	if boundary.file != nil && !boundary.fileClosed {
		boundary.fileClosed = true
		boundary.closeErr = boundary.file.Close()
	}
	return boundary.closeErr
}

// Verify checks the complete current directory, original inode and full bytes.
func (boundary *DownloadBoundary) Verify() error {
	if !boundary.ownsIdentity() {
		return ErrDownloadBoundaryChanged
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return boundary.verify()
}

func (boundary *DownloadBoundary) verify() error {
	entries, info, err := ReadDirectory(boundary.directory, 1)
	if err != nil || boundary.directoryInfo == nil || !os.SameFile(boundary.directoryInfo, info) {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	if len(entries) != 1 || entries[0].Name() != "go.mod" || boundary.fileInfo == nil {
		return ErrDownloadBoundaryChanged
	}
	actual, err := os.Lstat(boundary.name)
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(boundary.fileInfo, actual) || actual.Size() != int64(len(boundary.written)) {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	snapshot := NewSnapshot()
	if err := snapshot.Retain(boundary.name); err != nil {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	data, err := snapshot.ReadRetained(boundary.name)
	if err != nil || !bytes.Equal(data, boundary.written) {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	after, err := os.Lstat(boundary.name)
	if err != nil || !os.SameFile(boundary.fileInfo, after) {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	if err := snapshot.Verify(); err != nil {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	entries, info, err = ReadDirectory(boundary.directory, 1)
	if err != nil || !os.SameFile(boundary.directoryInfo, info) || len(entries) != 1 || entries[0].Name() != "go.mod" {
		return errors.Join(ErrDownloadBoundaryChanged, err)
	}
	return nil
}

// Close is nonrecursive and refuses foreign members, bytes or inode changes.
func (boundary *DownloadBoundary) Close() error {
	if boundary == nil {
		return nil
	}
	if !boundary.ownsIdentity() {
		return ErrDownloadBoundaryChanged
	}
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return boundary.close()
}

func (boundary *DownloadBoundary) close() error {
	result := boundary.closeFile()
	if boundary.directoryRemoved {
		return result
	}
	if boundary.fileInfo != nil && !boundary.fileRemoved {
		if err := boundary.verify(); err != nil {
			return errors.Join(result, err)
		}
		if err := os.Remove(boundary.name); err != nil {
			return errors.Join(result, err)
		}
		boundary.fileRemoved = true
	}
	entries, info, err := ReadDirectory(boundary.directory, 0)
	if err != nil || boundary.directoryInfo == nil || !os.SameFile(boundary.directoryInfo, info) || len(entries) != 0 {
		return errors.Join(result, ErrDownloadBoundaryChanged, err)
	}
	err = os.Remove(boundary.directory)
	if err == nil {
		boundary.directoryRemoved = true
	}
	return errors.Join(result, err)
}
