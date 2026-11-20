package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// This cache is opt-in. In particular, source/cache mutation tests retain
// their own directories and the caller's global build cache is never changed.
var fixedLocalProcessToolCache testToolCache

type testToolCache struct {
	mu        sync.Mutex
	temporary string
	path      string
	info      os.FileInfo
	closed    bool
}

func (cache *testToolCache) directory() (string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.closed {
		return "", fmt.Errorf("test compiler cache is closed")
	}
	if cache.path == "" {
		directory, err := os.MkdirTemp(cache.temporary, "plan9asm-test-compiler-cache-")
		if err != nil {
			return "", err
		}
		canonical, err := filepath.EvalSymlinks(directory)
		if err != nil {
			return "", fmt.Errorf("resolve test compiler cache: %w; cleanup: %v", err, os.RemoveAll(directory))
		}
		info, err := os.Lstat(canonical)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("inspect test compiler cache: %v; cleanup: %v", err, os.RemoveAll(directory))
		}
		cache.path, cache.info = canonical, info
	}
	info, err := os.Lstat(cache.path)
	if err != nil || !info.IsDir() || !os.SameFile(cache.info, info) {
		return "", fmt.Errorf("test compiler cache directory identity changed: %v", err)
	}
	return cache.path, nil
}

func (cache *testToolCache) close() error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.closed = true
	if cache.path == "" {
		return nil
	}
	info, err := os.Lstat(cache.path)
	if err != nil || !info.IsDir() || !os.SameFile(cache.info, info) {
		return fmt.Errorf("refusing to remove a replaced test compiler cache: %v", err)
	}
	if err := os.RemoveAll(cache.path); err != nil {
		return fmt.Errorf("remove test compiler cache: %w", err)
	}
	cache.path, cache.info = "", nil
	return nil
}

func TestMain(m *testing.M) {
	// A root may temporarily redirect TMPDIR/TMP/TEMP into its own TempDir.
	// That root's cleanup must not own this longer-lived, lazily created cache.
	fixedLocalProcessToolCache.temporary = os.TempDir()
	status := m.Run()
	if err := fixedLocalProcessToolCache.close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		status = 1
	}
	os.Exit(status)
}
