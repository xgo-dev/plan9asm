package gooriginalsrc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// ReadDirectory returns a complete bounded physical inventory, not a source
// capability. Consumers select their own fixed limit and retain its identity.
func ReadDirectory(name string, maximum int) (_ []os.DirEntry, _ os.FileInfo, result error) {
	if !filepath.IsAbs(name) || maximum < 0 || maximum > fileLimit+directoryLimit {
		return nil, nil, fmt.Errorf("original directory has no absolute bounded inventory role")
	}
	physical, err := sourcepath.Resolve(name)
	before, statErr := os.Lstat(physical)
	if err != nil || statErr != nil || !before.IsDir() {
		return nil, nil, errors.Join(err, statErr, fmt.Errorf("original directory is unavailable"))
	}
	file, err := os.Open(physical)
	if err != nil {
		return nil, nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(before, opened) {
		return nil, nil, errors.Join(err, fmt.Errorf("original directory changed while opening"))
	}
	entries, err := file.ReadDir(maximum + 1)
	if err != nil && err != io.EOF {
		return nil, nil, err
	}
	if len(entries) > maximum {
		return nil, nil, fmt.Errorf("original directory inventory exceeds its count bound")
	}
	// ReadDir may return its last nonempty batch without EOF. Require a further
	// empty read with real EOF; a bounded prefix must never become a success.
	if extra, err := file.ReadDir(1); len(extra) != 0 || err != io.EOF {
		return nil, nil, errors.Join(err, fmt.Errorf("original directory inventory lacks complete EOF"))
	}
	after, statErr := os.Lstat(physical)
	resolved, resolveErr := sourcepath.Resolve(name)
	if statErr != nil || resolveErr != nil || resolved != physical || !after.IsDir() ||
		!os.SameFile(opened, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, nil, errors.Join(statErr, resolveErr, fmt.Errorf("original directory identity or generation changed while reading"))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, before, nil
}
