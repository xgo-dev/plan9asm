package gooriginalsrc

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

func (set *OriginSet) moduleHashes(ctx context.Context, root, path, version, archive string) (zipSum, dirSum string, result error) {
	result = set.withOriginalZIP(ctx, module.Version{Path: path, Version: version}, archive, func(reader *zip.Reader) error {
		var err error
		zipSum, dirSum, err = set.moduleReaderHashes(ctx, root, path, version, reader)
		return err
	})
	return
}

func (set *OriginSet) moduleReaderHashes(ctx context.Context, root, path, version string, reader *zip.Reader) (string, string, error) {
	if len(reader.File) > fileLimit {
		return "", "", fmt.Errorf("original ZIP member inventory exceeds its count bound")
	}
	key := path + "@" + version
	physical := make(map[string]string)
	var treeBytes int64
	for name, info := range set.files.files {
		relative, err := filepath.Rel(root, name)
		if err != nil || !filepath.IsLocal(relative) {
			continue
		}
		member := key + "/" + filepath.ToSlash(relative)
		physical[member] = name
		treeBytes += info.Size()
	}
	if treeBytes > modzip.MaxZipFile || treeBytes > set.files.bytes || set.files.bytes > set.files.byteLimit() {
		return "", "", fmt.Errorf("original ZIP/tree escaped its shared inventory byte bound")
	}
	members := make(map[string]*zip.File)
	var names []string
	var zipBytes int64
	for _, member := range reader.File {
		if _, duplicate := members[member.Name]; duplicate {
			return "", "", fmt.Errorf("original ZIP contains a duplicate member")
		}
		original, exists := physical[member.Name]
		if !exists {
			return "", "", fmt.Errorf("original ZIP member has no complete retained tree role")
		}
		extent := set.files.files[original].Size()
		if extent < 0 || member.UncompressedSize64 > modzip.MaxZipFile || member.UncompressedSize64 != uint64(extent) {
			return "", "", fmt.Errorf("original ZIP member extent differs from its bounded retained tree role")
		}
		zipBytes += extent
		if zipBytes > treeBytes {
			return "", "", fmt.Errorf("original ZIP members exceed their retained tree extent")
		}
		members[member.Name] = member
		names = append(names, member.Name)
	}
	if len(members) != len(physical) || zipBytes != treeBytes {
		return "", "", fmt.Errorf("original ZIP/tree complete member inventories differ")
	}
	zipSum, err := hashOriginalMembers(names, func(name string) (io.ReadCloser, error) {
		member := members[name]
		reader, err := member.Open()
		if err != nil {
			return nil, err
		}
		return &originalZIPReader{reader: reader, expected: int64(member.UncompressedSize64), ctx: ctx}, nil
	})
	if err != nil {
		return "", "", err
	}
	dirSum, err := hashOriginalMembers(names, func(name string) (io.ReadCloser, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		reader, err := set.files.OpenRetained(physical[name])
		if err != nil {
			return nil, err
		}
		return &originalContextReader{ReadCloser: reader, ctx: ctx}, nil
	})
	return zipSum, dirSum, err
}

// Stream the retained archive into a private validation scratch. Both Go's
// path-only validator and ZIP member consumers use those same guarded bytes,
// without buffering a whole module ZIP in memory or replacing its source root.
func (set *OriginSet) withOriginalZIP(ctx context.Context, identity module.Version, archive string, consume func(*zip.Reader) error) (result error) {
	owned, err := os.MkdirTemp(set.cache, "plan9asm-original-zip-check-")
	if err != nil {
		return err
	}
	directoryInfo, err := os.Lstat(owned)
	if err != nil {
		return err
	}
	name := filepath.Join(owned, "original.zip")
	var fileInfo os.FileInfo
	defer func() {
		actual, statErr := os.Lstat(owned)
		physical, resolveErr := sourcepath.Resolve(owned)
		entries, _, readErr := ReadDirectory(owned, 1)
		if statErr != nil || resolveErr != nil || readErr != nil || physical != owned ||
			!actual.IsDir() || !os.SameFile(directoryInfo, actual) {
			result = errors.Join(result, fmt.Errorf("owned ZIP validation directory identity changed"))
			return
		}
		if fileInfo == nil {
			if len(entries) != 0 {
				result = errors.Join(result, fmt.Errorf("owned ZIP validation inventory is unclosed"))
				return
			}
		} else {
			actual, err := os.Lstat(name)
			if err != nil || len(entries) != 1 || entries[0].Name() != "original.zip" ||
				!actual.Mode().IsRegular() || !os.SameFile(fileInfo, actual) {
				result = errors.Join(result, fmt.Errorf("owned ZIP validation file identity changed"))
				return
			}
		}
		result = errors.Join(result, os.RemoveAll(owned))
	}()
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	fileInfo, err = file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	reader, err := set.files.OpenRetained(archive)
	if err != nil {
		return errors.Join(err, file.Close())
	}
	writeErr := copyOriginalFile(file, &originalContextReader{ReadCloser: reader, ctx: ctx})
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	afterWrite, err := os.Lstat(name)
	if err != nil || !afterWrite.Mode().IsRegular() || !os.SameFile(fileInfo, afterWrite) || afterWrite.Size() != set.files.files[archive].Size() {
		return errors.Join(err, fmt.Errorf("owned ZIP validation file changed while writing"))
	}
	fileInfo = afterWrite
	expected := set.files.hashes[archive]
	verify := func() error {
		actualDirectory, statErr := os.Lstat(owned)
		entries, _, readErr := ReadDirectory(owned, 1)
		if statErr != nil || readErr != nil || !actualDirectory.IsDir() || !os.SameFile(directoryInfo, actualDirectory) ||
			len(entries) != 1 || entries[0].Name() != "original.zip" {
			return errors.Join(statErr, readErr, fmt.Errorf("owned ZIP validation directory/inventory changed"))
		}
		actual, err := originalRoleFileSHA256(name, fileInfo, originalModuleArtifact)
		if err != nil || actual != expected {
			return errors.Join(err, fmt.Errorf("owned ZIP validation bytes changed"))
		}
		return nil
	}
	if err := verify(); err != nil {
		return err
	}
	_, checkErr := modzip.CheckZip(identity, name)
	if err := errors.Join(checkErr, verify()); err != nil {
		return err
	}
	zipReader, err := zip.OpenReader(name)
	if err != nil {
		return err
	}
	consumeErr := consume(&zipReader.Reader)
	return errors.Join(consumeErr, zipReader.Close(), verify(), ctx.Err())
}

// Go Hash1 intentionally ignores Close errors. Accumulate them independently
// so failed physical EOF/CRC/resource closure cannot become an h1 success.
func hashOriginalMembers(names []string, open func(string) (io.ReadCloser, error)) (string, error) {
	var closeErr error
	sum, err := dirhash.Hash1(names, func(name string) (io.ReadCloser, error) {
		reader, err := open(name)
		if err != nil {
			return nil, err
		}
		return &originalCloseReader{ReadCloser: reader, result: &closeErr}, nil
	})
	return sum, errors.Join(err, closeErr)
}

type originalCloseReader struct {
	io.ReadCloser
	result *error
}

func (reader *originalCloseReader) Close() error {
	err := reader.ReadCloser.Close()
	*reader.result = errors.Join(*reader.result, err)
	return err
}

type originalContextReader struct {
	io.ReadCloser
	ctx context.Context
}

func (reader *originalContextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.ReadCloser.Read(data)
}

func (reader *originalContextReader) Close() error {
	return errors.Join(reader.ctx.Err(), reader.ReadCloser.Close())
}

type originalZIPReader struct {
	reader   io.ReadCloser
	ctx      context.Context
	expected int64
	count    int64
	complete bool
	closed   bool
	failure  error
}

func (reader *originalZIPReader) Read(data []byte) (int, error) {
	if reader.failure != nil {
		return 0, reader.failure
	}
	if reader.closed {
		return 0, os.ErrClosed
	}
	if reader.complete {
		return 0, io.EOF
	}
	if err := reader.ctx.Err(); err != nil {
		reader.failure = err
		return 0, err
	}
	if remaining := reader.expected - reader.count + 1; int64(len(data)) > remaining {
		data = data[:int(remaining)]
	}
	count, err := reader.reader.Read(data)
	reader.count += int64(count)
	if reader.count > reader.expected || err == io.EOF && reader.count != reader.expected {
		err = fmt.Errorf("original ZIP member did not close its complete retained extent")
	} else if err == io.EOF {
		reader.complete = true
	}
	if err != nil && err != io.EOF {
		reader.failure = err
	}
	return count, err
}

func (reader *originalZIPReader) Close() error {
	if reader.closed {
		return reader.failure
	}
	reader.closed = true
	if !reader.complete {
		reader.failure = errors.Join(reader.failure, fmt.Errorf("original ZIP member lacks complete EOF/CRC"))
	}
	reader.failure = errors.Join(reader.failure, reader.ctx.Err(), reader.reader.Close())
	return reader.failure
}
