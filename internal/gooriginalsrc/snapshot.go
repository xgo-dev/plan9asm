// Package gooriginalsrc observes bounded original files and exact Go-download
// origins. Its state is byte/role consistency data, never an ASM capability.
package gooriginalsrc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	modzip "golang.org/x/mod/zip"
)

var originalHashBuffers = sync.Pool{New: func() any { return new([64 << 10]byte) }}

const (
	fileLimit      = 65536
	directoryLimit = 4096
	fileByteLimit  = 16 << 20
	toolByteLimit  = 64 << 20
	// A current ordinary cross-target SDK source/export graph plus its
	// independently selected Go driver exceeds 64 MiB (71,297,622 bytes in
	// the measured crypto witness). Keep one finite shared 128 MiB budget.
	// Hashing remains streaming; per-file and role/count bounds are unchanged.
	totalByteLimit = 128 << 20
)

type originalFileRole uint8

const (
	originalSourceFile originalFileRole = iota + 1
	originalToolFile
	originalModuleArtifact
)

func (role originalFileRole) byteLimit() int64 {
	switch role {
	case originalSourceFile:
		return fileByteLimit
	case originalToolFile:
		// This is the existing Go frame driver/subtool physical-read limit.
		// Sources, exports and ZIP members do not acquire the tool role.
		return toolByteLimit
	case originalModuleArtifact:
		return modzip.MaxZipFile
	default:
		return -1
	}
}

// Snapshot retains complete physical files and directory membership. It has no
// serialized constructor, command callback, frame, signature or permission.
type Snapshot struct {
	hashes, paths   map[string]string
	entries         map[string][]string
	directories     map[string]os.FileInfo
	files           map[string]os.FileInfo
	retainedRoles   map[string]originalFileRole
	tools           map[string]os.FileInfo
	fileRoles       map[string]bool
	directoryRoles  map[string]bool
	bytes           int64
	moduleArtifacts bool
}

// SnapshotView is the existing producer's observation data. These maps expose
// no capability: consumers must retain their own actual Snapshot and Verify it.
// The compatibility producer uses this view rather than duplicating inventories.
type SnapshotView struct {
	Hashes, Paths map[string]string
	Entries       map[string][]string
	Directories   map[string]os.FileInfo
}

func NewSnapshot() *Snapshot {
	return &Snapshot{
		hashes: make(map[string]string), paths: make(map[string]string),
		entries: make(map[string][]string), directories: make(map[string]os.FileInfo),
		files:         make(map[string]os.FileInfo),
		retainedRoles: make(map[string]originalFileRole), tools: make(map[string]os.FileInfo),
		fileRoles: make(map[string]bool), directoryRoles: make(map[string]bool),
	}
}

func (snapshot *Snapshot) View() SnapshotView {
	return SnapshotView{snapshot.hashes, snapshot.paths, snapshot.entries, snapshot.directories}
}

func (snapshot *Snapshot) Retain(name string) error {
	if snapshot != nil && snapshot.moduleArtifacts {
		return snapshot.retain(name, originalModuleArtifact)
	}
	return snapshot.retain(name, originalSourceFile)
}

// Only the exact module-origin factory uses this inventory. It retains a
// complete Go-bounded archive and extracted tree, not a larger source/parser
// buffer. The ordinary SDK/source/export inventory keeps its existing limits.
func newModuleSnapshot() *Snapshot {
	snapshot := NewSnapshot()
	snapshot.moduleArtifacts = true
	return snapshot
}

func (snapshot *Snapshot) byteLimit() int64 {
	if snapshot.moduleArtifacts {
		// One finite graph budget can hold a maximum-size Go module's ZIP
		// and extracted tree plus the existing tool/metadata budget. Each
		// module is also checked against Go's independent 500 MiB limits.
		return 2*modzip.MaxZipFile + totalByteLimit
	}
	return totalByteLimit
}

// RetainTool observes an explicitly selected original driver/subtool, using
// the existing 64 MiB tool contract. It shares the original graph budget and
// cannot be read as source bytes or mint source/frame/ASM permissions.
func (snapshot *Snapshot) RetainTool(name string) error {
	return snapshot.retain(name, originalToolFile)
}

func (snapshot *Snapshot) retain(name string, role originalFileRole) error {
	if snapshot == nil || snapshot.hashes == nil || snapshot.retainedRoles == nil ||
		!filepath.IsAbs(name) || role.byteLimit() < 0 {
		return fmt.Errorf("original file path is missing or over-bound")
	}
	if _, retained := snapshot.hashes[name]; !retained && len(snapshot.hashes) >= fileLimit {
		return fmt.Errorf("original file inventory exceeds its count bound")
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > role.byteLimit() {
		return fmt.Errorf("original source/export is missing, nonregular or over-bound: %s", filepath.Base(name))
	}
	if prior, exists := snapshot.retainedRoles[name]; exists && prior != role {
		return fmt.Errorf("original physical file cannot be relabeled between source and tool")
	}
	// Tools are a small explicitly selected inventory. Check their original
	// inode as well as the path so hard links and case/parent aliases cannot
	// turn the same physical file into the other observation role.
	if role != originalToolFile {
		for _, tool := range snapshot.tools {
			if os.SameFile(tool, info) {
				return fmt.Errorf("original tool inode cannot be relabeled as source")
			}
		}
	} else {
		for prior, file := range snapshot.files {
			if snapshot.retainedRoles[prior] != originalToolFile && os.SameFile(file, info) {
				return fmt.Errorf("original source inode cannot be relabeled as tool")
			}
		}
	}
	physical, err := sourcepath.Resolve(name)
	if err != nil {
		return err
	}
	if !snapshot.fileRoles[physical] && len(snapshot.fileRoles) >= fileLimit {
		return fmt.Errorf("original file member inventory exceeds its shared count bound")
	}
	digest, err := originalRoleFileSHA256(name, info, role)
	if err != nil {
		return err
	}
	if prior, present := snapshot.hashes[name]; present {
		if prior != digest || snapshot.paths[name] != physical || !os.SameFile(snapshot.files[name], info) {
			return fmt.Errorf("original source/export changed during capture")
		}
	} else {
		if info.Size() > snapshot.byteLimit()-snapshot.bytes {
			return fmt.Errorf("original source/export inventory exceeds its byte bound: retained=%d incoming=%d limit=%d",
				snapshot.bytes, info.Size(), snapshot.byteLimit())
		}
		snapshot.bytes += info.Size()
	}
	snapshot.hashes[name], snapshot.paths[name], snapshot.files[name] = digest, physical, info
	snapshot.retainedRoles[name] = role
	if role == originalToolFile {
		snapshot.tools[name] = info
	}
	snapshot.fileRoles[physical] = true
	return nil
}

func (snapshot *Snapshot) Directory(name string, recursive bool) error {
	if snapshot == nil || snapshot.directories == nil || !filepath.IsAbs(name) {
		return fmt.Errorf("original source directory requires an absolute initialized role")
	}
	if _, retained := snapshot.directories[name]; !retained && len(snapshot.directories) >= directoryLimit {
		return fmt.Errorf("original source directory inventory exceeds its count bound")
	}
	physical, err := sourcepath.Resolve(name)
	if err != nil {
		return err
	}
	entries, info, err := ReadDirectory(name, fileLimit+directoryLimit)
	if err != nil {
		return err
	}
	if prior, present := snapshot.directories[name]; present &&
		(!os.SameFile(prior, info) || snapshot.paths[name] != physical) {
		return fmt.Errorf("original source directory identity changed")
	}
	newFiles, newDirectories := make(map[string]bool), make(map[string]bool)
	if !snapshot.directoryRoles[physical] {
		newDirectories[physical] = true
	}
	for _, entry := range entries {
		child := filepath.Join(physical, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("original source directory contains an unbound nonregular entry")
		}
		if entry.IsDir() {
			if !snapshot.directoryRoles[child] {
				newDirectories[child] = true
			}
		} else if !snapshot.fileRoles[child] {
			newFiles[child] = true
		}
	}
	if len(snapshot.fileRoles)+len(newFiles) > fileLimit || len(snapshot.directoryRoles)+len(newDirectories) > directoryLimit {
		return fmt.Errorf("complete original directory members exceed the shared graph count bound")
	}
	for child := range newFiles {
		snapshot.fileRoles[child] = true
	}
	for child := range newDirectories {
		snapshot.directoryRoles[child] = true
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		child := filepath.Join(physical, entry.Name())
		names = append(names, entry.Name()+":"+entry.Type().String())
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("original source directory contains an unbound nonregular entry")
		}
		if recursive {
			if entry.IsDir() {
				if err := snapshot.Directory(child, true); err != nil {
					return err
				}
			} else if err := snapshot.Retain(child); err != nil {
				return err
			}
		}
	}
	if prior, present := snapshot.entries[name]; present && !reflect.DeepEqual(prior, names) {
		return fmt.Errorf("original source directory membership changed during capture")
	}
	snapshot.entries[name], snapshot.paths[name], snapshot.directories[name] = names, physical, info
	return nil
}

func (snapshot *Snapshot) Verify() error {
	if snapshot == nil || snapshot.hashes == nil || snapshot.files == nil ||
		snapshot.retainedRoles == nil || snapshot.directories == nil {
		return fmt.Errorf("missing original source/export inventory")
	}
	for name, digest := range snapshot.hashes {
		info, err := os.Lstat(name)
		physical, resolveErr := sourcepath.Resolve(name)
		if err != nil || resolveErr != nil || !info.Mode().IsRegular() ||
			physical != snapshot.paths[name] || !os.SameFile(snapshot.files[name], info) {
			return fmt.Errorf("original source/export physical identity changed")
		}
		actual, err := originalRoleFileSHA256(name, snapshot.files[name], snapshot.retainedRoles[name])
		if err != nil {
			return fmt.Errorf("original source/export bytes changed: %w", err)
		}
		if actual != digest {
			return fmt.Errorf("original source/export bytes changed")
		}
	}
	for name := range snapshot.directories {
		physical, err := sourcepath.Resolve(name)
		entries, info, readErr := ReadDirectory(name, fileLimit+directoryLimit)
		if err != nil || readErr != nil || physical != snapshot.paths[name] ||
			!os.SameFile(snapshot.directories[name], info) {
			return fmt.Errorf("original source directory identity changed")
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name()+":"+entry.Type().String())
		}
		if !reflect.DeepEqual(names, snapshot.entries[name]) {
			return fmt.Errorf("original source directory membership changed")
		}
	}
	return nil
}

// ReadRetained reads only an independently retained physical file, using a
// 16 MiB source-buffer bound and the streaming hash's complete EOF guard.
// Larger module artifacts remain stream-only; these bytes grant no permission.
func (snapshot *Snapshot) ReadRetained(name string) ([]byte, error) {
	if snapshot == nil || snapshot.files[name] == nil || snapshot.files[name].Size() > fileByteLimit {
		return nil, fmt.Errorf("retained source buffer exceeds its byte bound")
	}
	reader, err := snapshot.OpenRetained(name)
	if err != nil {
		return nil, err
	}
	buffer := &originalFileBuffer{bytes: make([]byte, int(snapshot.files[name].Size()))}
	err = copyOriginalFile(buffer, reader)
	if err != nil {
		return nil, err
	}
	return buffer.bytes, nil
}

// OpenRetained exposes only an observed source/member's strict physical stream
// under its own role's limit, never a compiler tool. Complete EOF and close
// errors must be consumed; this does not enlarge ReadRetained's buffer limit
// or mint source/frame permissions.
func (snapshot *Snapshot) OpenRetained(name string) (io.ReadCloser, error) {
	if snapshot == nil || !filepath.IsAbs(name) {
		return nil, fmt.Errorf("missing retained original file role")
	}
	expected := snapshot.files[name]
	digest, retained := snapshot.hashes[name]
	physical, err := sourcepath.Resolve(name)
	if !retained || expected == nil || err != nil || physical != snapshot.paths[name] ||
		snapshot.retainedRoles[name] != originalSourceFile && snapshot.retainedRoles[name] != originalModuleArtifact {
		return nil, fmt.Errorf("original file was not retained at its physical role")
	}
	role := snapshot.retainedRoles[name]
	if expected.Size() < 0 || expected.Size() > role.byteLimit() {
		return nil, fmt.Errorf("retained original file exceeds its byte bound")
	}
	return openOriginalRoleFile(name, expected, physical, digest, role)
}

// A fixed extent prevents io.Copy from allocating extra storage if an original
// metadata file grows after the observation. Overflow rejects, never truncates.
type originalFileBuffer struct {
	bytes  []byte
	offset int
}

func (buffer *originalFileBuffer) Write(data []byte) (int, error) {
	if len(data) > len(buffer.bytes)-buffer.offset {
		return 0, fmt.Errorf("original source file grew beyond its retained extent")
	}
	count := copy(buffer.bytes[buffer.offset:], data)
	buffer.offset += count
	return count, nil
}

func originalFileSHA256(name string, expected os.FileInfo) (string, error) {
	return originalRoleFileSHA256(name, expected, originalSourceFile)
}

func originalRoleFileSHA256(name string, expected os.FileInfo, role originalFileRole) (string, error) {
	physical, err := sourcepath.Resolve(name)
	if err != nil {
		return "", err
	}
	reader, err := openOriginalRoleFile(name, expected, physical, "", role)
	if err != nil {
		return "", err
	}
	if err := copyOriginalFile(io.Discard, reader); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", reader.hash.Sum(nil)), nil
}

func copyOriginalFile(output io.Writer, reader io.ReadCloser) error {
	buffer := originalHashBuffers.Get().(*[64 << 10]byte)
	defer originalHashBuffers.Put(buffer)
	_, err := io.CopyBuffer(output, reader, buffer[:])
	return errors.Join(err, reader.Close())
}

type originalFileReader struct {
	file     *os.File
	name     string
	physical string
	expected os.FileInfo
	digest   string
	hash     hash.Hash
	count    int64
	complete bool
	closed   bool
	failure  error
}

func openOriginalFile(name string, expected os.FileInfo, physical, digest string) (*originalFileReader, error) {
	return openOriginalRoleFile(name, expected, physical, digest, originalSourceFile)
}

func openOriginalRoleFile(name string, expected os.FileInfo, physical, digest string, role originalFileRole) (*originalFileReader, error) {
	if expected == nil || role.byteLimit() < 0 || expected.Size() < 0 || expected.Size() > role.byteLimit() {
		return nil, fmt.Errorf("original source file has no bounded physical extent")
	}
	before, err := os.Lstat(name)
	resolved, resolveErr := sourcepath.Resolve(name)
	if err != nil || resolveErr != nil || resolved != physical || !before.Mode().IsRegular() ||
		!os.SameFile(expected, before) || before.Size() != expected.Size() {
		return nil, fmt.Errorf("original source file identity or extent changed before opening")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() != expected.Size() {
		return nil, errors.Join(fmt.Errorf("original source file identity changed while opening"), file.Close())
	}
	return &originalFileReader{file: file, name: name, physical: physical,
		expected: expected, digest: digest, hash: sha256.New()}, nil
}

func (reader *originalFileReader) Read(data []byte) (int, error) {
	if reader.failure != nil {
		return 0, reader.failure
	}
	if reader.closed {
		return 0, os.ErrClosed
	}
	if reader.complete {
		return 0, io.EOF
	}
	if remaining := reader.expected.Size() - reader.count + 1; int64(len(data)) > remaining {
		data = data[:int(remaining)]
	}
	count, err := reader.file.Read(data)
	reader.count += int64(count)
	_, _ = reader.hash.Write(data[:count])
	if reader.count > reader.expected.Size() {
		err = fmt.Errorf("original source file grew beyond its retained extent")
	} else if err == io.EOF {
		after, statErr := os.Lstat(reader.name)
		physical, resolveErr := sourcepath.Resolve(reader.name)
		if statErr != nil || resolveErr != nil || physical != reader.physical || !after.Mode().IsRegular() ||
			!os.SameFile(reader.expected, after) || reader.count != reader.expected.Size() || reader.count != after.Size() ||
			reader.digest != "" && fmt.Sprintf("%x", reader.hash.Sum(nil)) != reader.digest {
			err = fmt.Errorf("original source file identity, bytes or extent changed while reading")
		} else {
			reader.complete = true
		}
	}
	if err != nil && err != io.EOF {
		reader.failure = err
	}
	return count, err
}

func (reader *originalFileReader) Close() error {
	if reader.closed {
		return reader.failure
	}
	reader.closed = true
	if !reader.complete {
		reader.failure = errors.Join(reader.failure, fmt.Errorf("original source member did not reach complete EOF"))
	}
	reader.failure = errors.Join(reader.failure, reader.file.Close())
	return reader.failure
}
