package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// An exact synthetic module served by an owned file proxy exercises the same
// actual download/ZIP path as production, without fetching external source.
func ordinaryFixtureDependency(t *testing.T, input *featureInput, module string, files map[string]string) string {
	return ordinaryFixtureDependencyOrigin(t, input, module, files, true)
}

func ordinaryFixtureDependencyOrigin(t *testing.T, input *featureInput, module string, files map[string]string, originalGoMod bool) string {
	t.Helper()
	proxy, cache := t.TempDir(), t.TempDir()
	metadata := "module " + module + "\n\ngo 1.20\n"
	if originalGoMod {
		files["go.mod"] = metadata
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(module + "@v1.0.0/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(proxy, module, "@v")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{
		".zip": archive.Bytes(), ".mod": []byte(metadata),
		".info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(directory, "v1.0.0"+suffix), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPROXY", proxyURL)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOPATH", t.TempDir())
	t.Cleanup(func() {
		if err := filepath.Walk(cache, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(file, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	mod := "module " + input.Module + "\n\ngo 1.24\nrequire " + module + " v1.0.0\n"
	if err := os.WriteFile(filepath.Join(input.SourceRoot, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["go.mod"] = featureBytesSHA256([]byte(mod))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	data, stderr, err := gotoolprofile.RunBounded(ctx, input.SourceRoot, featureEnvironment(os.Environ(), input.Observed.Environment), binary, "mod", "download", "-json", module+"@v1.0.0")
	if err != nil {
		t.Fatalf("actual owned proxy download: %v\n%s", err, stderr)
	}
	var actual struct{ Dir, Error string }
	if err := json.Unmarshal(data, &actual); err != nil || actual.Error != "" || actual.Dir == "" {
		t.Fatalf("actual proxy identity: %s; %v", data, err)
	}
	if data, err := os.ReadFile(filepath.Join(input.SourceRoot, "go.sum")); err != nil {
		t.Fatal(err)
	} else {
		input.Sources["go.sum"] = featureBytesSHA256(data)
		input.Directories["."] = append(input.Directories["."], "go.sum")
		sort.Strings(input.Directories["."])
	}
	return actual.Dir
}
