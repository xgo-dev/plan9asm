package gotoolprofile

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// The file proxy contains only this repository's generated first-party code.
// GOSUMDB=off here is not a production source-authentication certificate.
func amd64DownloadedObservationFixture(t *testing.T, variant string) (AMD64OriginalObservationRequest, string, string) {
	t.Helper()
	withoutGo := strings.HasSuffix(variant, "-no-go")
	variant = strings.TrimSuffix(variant, "-no-go")
	baseVariant := variant
	if variant == "nested-import" || variant == "nested-foreign" {
		baseVariant = "nested"
	}
	request := amd64OriginalObservationFixture(t, baseVariant)
	fixedNested := strings.HasPrefix(variant, "fixed-local-nested")
	if variant == "fixed-local" || fixedNested {
		request, _, _, _, _ = amd64OriginalFixedLocalFixture(t)
	}
	modulePath, version := "example.invalid/observation", "v1.0.0"
	if variant == "incompatible" {
		version = "v1.0.0+incompatible"
	}
	if variant == "alias" {
		modulePath = "example.invalid/archive-observation"
	}
	proxy, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := request.Directory
	if fixedNested {
		request.Directory = filepath.Join(root, "internal", "kernel")
		request.PackagePath += "/internal/kernel"
		if err := os.MkdirAll(request.Directory, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"value.go", "value_amd64.s", "local.h"} {
			if err := os.Rename(filepath.Join(root, name), filepath.Join(request.Directory, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if baseVariant == "nested" {
		root = filepath.Dir(filepath.Dir(root))
	}
	if strings.HasSuffix(variant, "-large-archive") || strings.HasSuffix(variant, "-large-payload") {
		directory := filepath.Join(root, "payload")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		members, extent := 3, int64(8<<20)
		if strings.HasSuffix(variant, "-large-payload") {
			members, extent = 1, 17<<20
		}
		for index := 0; index < members; index++ {
			file, err := os.Create(filepath.Join(directory, string(rune('a'+index))+".bin"))
			if err != nil {
				t.Fatal(err)
			}
			// A sparse zero-filled first-party payload needs no large allocation.
			if err := errors.Join(file.Truncate(extent), file.Close()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if variant == "nested-import" {
		data := "package observation\nimport \"math/bits\"\nfunc Value(a uint64) uint64\n" +
			"func Reference(a uint64) uint64 { return bits.RotateLeft64(a, 1) }\n"
		if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := filepath.WalkDir(cache, func(name string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(name, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
	if err != nil {
		t.Fatal(err)
	}
	request.Environment = replaceEnv(request.Environment, map[string]string{
		"GOPROXY": proxyURL, "GOMODCACHE": cache,
	})
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	if variant == "foreign" || variant == "nested-foreign" {
		foreignRoot := t.TempDir()
		foreignModule := "example.invalid/foreign-observation"
		foreignGoMod := "module " + foreignModule + "\ngo 1.20\n"
		if withoutGo {
			foreignGoMod = "module " + foreignModule + "\n"
		}
		for name, data := range map[string]string{
			"go.mod":   foreignGoMod,
			"shape.go": "package shape\ntype Word uint64\n",
		} {
			if err := os.WriteFile(filepath.Join(foreignRoot, name), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		writeAMD64ObservationModuleProxy(t, proxy, foreignModule, version, foreignRoot)
		if err := os.WriteFile(filepath.Join(root, "go.mod"),
			[]byte("module example.invalid/observation\ngo 1.20\nrequire "+foreignModule+" "+version+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(request.Directory, "value.go"),
			[]byte("package observation\nimport shape \""+foreignModule+"\"\nfunc Value(a shape.Word) uint64\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := RunBounded(ctx, root, request.Environment, request.GoBinary,
			"mod", "download", "-json", foreignModule+"@"+version)
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual generated foreign module download: %v; %s", err, stderr)
		}
	}
	if withoutGo {
		name := filepath.Join(root, "go.mod")
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "\ngo 1.20\n") {
			t.Fatal("first-party fixture lost its explicit language control")
		}
		data = []byte(strings.Replace(string(data), "\ngo 1.20\n", "\n", 1))
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	method := uint16(zip.Deflate)
	if strings.HasSuffix(variant, "-large-archive") {
		method = zip.Store
	}
	writeAMD64ObservationModuleProxyWithMethod(t, proxy, modulePath, version, root, method)
	data, stderr, err := RunBounded(ctx, root, request.Environment, request.GoBinary,
		"mod", "download", "-json", modulePath+"@"+version)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual generated module download: %v; %s", err, stderr)
	}
	var downloaded struct{ Path, Version, Dir, Error string }
	if err := json.Unmarshal(data, &downloaded); err != nil || downloaded.Error != "" ||
		downloaded.Path != modulePath || downloaded.Version != version || downloaded.Dir == "" {
		t.Fatalf("actual Go omitted its exact downloaded source identity: %v", err)
	}
	request.Directory = downloaded.Dir
	if baseVariant == "nested" || fixedNested {
		request.Directory = filepath.Join(downloaded.Dir, "internal", "kernel")
	}
	return request, modulePath, version
}

func writeAMD64ObservationModuleProxy(t *testing.T, proxy, modulePath, version, root string) {
	t.Helper()
	writeAMD64ObservationModuleProxyWithMethod(t, proxy, modulePath, version, root, zip.Deflate)
}

func writeAMD64ObservationModuleProxyWithMethod(t *testing.T, proxy, modulePath, version, root string, method uint16) {
	t.Helper()
	dir := filepath.Join(proxy, modulePath, "@v")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(archive)
	err = filepath.WalkDir(root, func(name string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		member, err := w.CreateHeader(&zip.FileHeader{
			Name: modulePath + "@" + version + "/" + filepath.ToSlash(relative), Method: method,
		})
		if err != nil {
			return err
		}
		input, err := os.Open(name)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(member, input)
		return errors.Join(copyErr, input.Close())
	})
	if err := errors.Join(err, w.Close(), archive.Close()); err != nil {
		t.Fatal(err)
	}
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{
		".mod":  goMod,
		".info": []byte(`{"Version":"` + version + `","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(dir, version+suffix), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Keep the source/download identity separate from Go's actual cached-CWD role.
func captureAMD64DownloadedForTest(ctx context.Context, request AMD64OriginalObservationRequest, modulePath, version string) (*AMD64OriginalPackageObservation, error) {
	return CaptureAMD64DownloadedPackageObservation(ctx, AMD64DownloadedObservationRequest{
		Original: request, SourceModule: modulePath, SourceVersion: version,
	}, RunBounded)
}

func TestAMD64DownloadedObservationActualOriginalCache(t *testing.T) {
	for _, variant := range []string{"nested", "data", "sibling", "alias", "foreign", "incompatible"} {
		t.Run(variant, func(t *testing.T) {
			request, modulePath, version := amd64DownloadedObservationFixture(t, variant)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			if old, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded); err == nil {
				old.Close()
				t.Fatal("downloaded source acquired an owned-main role without an authenticated handoff")
			}
			observed, err := captureAMD64DownloadedForTest(ctx, request, modulePath, version)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			pkg := observed.state.packages[request.PackagePath]
			declaration := "func(a uint64) uint64"
			if variant == "foreign" {
				declaration = "func(a example.invalid/foreign-observation.Word) uint64"
				if len(observed.downloaded.modules) != 2 || observed.state.packages["example.invalid/foreign-observation"].Export == "" {
					t.Fatal("foreign source did not get its separate exact download/export handoff")
				}
			}
			if pkg.Module == nil || !pkg.Module.Main || pkg.Module.Version != "" || observed.state.declarations["Value"] != declaration {
				t.Fatal("actual original cache selection or complete checked declaration was lost")
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(pkg.Dir, "@"+version) {
				t.Fatal("source was copied into a synthetic owned main instead of observing original cache bytes")
			}
		})
	}
}
