package gooriginalsrc

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// HashRegularFile streams every current byte of a canonical bounded file. The
// existing physical reader checks opening/EOF identity, extent and close errors.
// This digest is not a retained Snapshot, source role or ASM capability. Each
// call opens and reads the file again; neither metadata nor a cache supplies it.
func HashRegularFile(name string, maximum int64) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	info, err := os.Lstat(name)
	if err != nil || !filepath.IsAbs(name) || !info.Mode().IsRegular() ||
		maximum < 0 || maximum > toolByteLimit || info.Size() < 0 || info.Size() > maximum {
		return result, fmt.Errorf("canonical regular file is missing or exceeds its byte bound")
	}
	reader, err := openOriginalRoleFile(name, info, name, "", originalToolFile)
	if err != nil {
		return result, err
	}
	// Hide io.Discard.ReaderFrom: CopyBuffer must use the existing pooled
	// 64-KiB buffer, not Discard's separate small-read fast path.
	if err := copyOriginalFile(struct{ io.Writer }{io.Discard}, reader); err != nil {
		return result, err
	}
	reader.hash.Sum(result[:0])
	return result, nil
}
