//go:build go1.27

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Only Go's content-addressed build artifacts may be shared with the caller.
// Every source observation, proof, command workspace and output stays private.
func x86SDKNumericalCLIBuildCache(t *testing.T) string {
	t.Helper()
	cache := os.Getenv("GOCACHE")
	if cache == "" {
		cache = t.TempDir()
	}
	selected, err := x86SDKNumericalCLICanonicalBuildCache(cache)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func x86SDKNumericalCLICanonicalBuildCache(cache string) (string, error) {
	if !filepath.IsAbs(cache) {
		return "", fmt.Errorf("selected GOCACHE must be an absolute existing directory: %q", cache)
	}
	selected, err := filepath.EvalSymlinks(cache)
	if err != nil {
		return "", fmt.Errorf("resolve selected GOCACHE: %w", err)
	}
	info, err := os.Stat(selected)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("selected GOCACHE is not an existing directory: %q: %v", selected, err)
	}
	return selected, nil
}

func TestX86SDKCLIBuildCacheRetainsCallerSelection(t *testing.T) {
	cache := t.TempDir()
	marker := filepath.Join(cache, "independent-build-artifact")
	if err := os.WriteFile(marker, []byte("caller-owned-content"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	want, err := filepath.EvalSymlinks(cache)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := x86SDKNumericalCLIBuildCache(t); got != want {
			t.Fatalf("selected build cache changed: %q want %q", got, want)
		}
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "caller-owned-content" {
		t.Fatalf("cache reuse changed the caller's artifacts: %q %v", data, err)
	}
}

func TestX86SDKCLIBuildCacheWithoutSelectionIsPrivate(t *testing.T) {
	t.Setenv("GOCACHE", "")
	first := x86SDKNumericalCLIBuildCache(t)
	second := x86SDKNumericalCLIBuildCache(t)
	if first == second {
		t.Fatal("absent caller selection unexpectedly shared independent fallback caches")
	}
	for _, selected := range []string{first, second} {
		info, err := os.Stat(selected)
		if err != nil || !info.IsDir() || !filepath.IsAbs(selected) {
			t.Fatalf("private fallback cache is not an existing absolute directory: %q %v", selected, err)
		}
	}
}

func TestX86SDKCLIBuildCacheRejectsInvalidSelection(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("not a cache"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, selected := range map[string]string{
		"empty": "", "disabled": "off", "relative": "relative-cache",
		"missing": filepath.Join(root, "missing"), "regular-file": file,
	} {
		t.Run(name, func(t *testing.T) {
			if cache, err := x86SDKNumericalCLICanonicalBuildCache(selected); err == nil || cache != "" {
				t.Fatalf("invalid selected cache passed or became an unrelated fallback: %q %q %v", selected, cache, err)
			}
		})
	}
}
