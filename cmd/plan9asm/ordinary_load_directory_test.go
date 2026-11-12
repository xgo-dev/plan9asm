package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSimplePackageLoadSDKWorkingDirectoryIdentity(t *testing.T) {
	actual, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "original-sdk")
	ordinaryLoadDirectoryAlias(t, alias, actual)
	for key, value := range map[string]string{
		"GOROOT": alias, "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
		"GOFLAGS": "", "GOPACKAGESDRIVER": "off", "GOOS": "linux", "GOARCH": "amd64",
	} {
		t.Setenv(key, value)
	}
	t.Setenv("CGO_ENABLED", "")
	if err := os.Unsetenv("CGO_ENABLED"); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(alias, "src", "hash", "crc32")
	t.Chdir(directory)
	t.Setenv("PWD", directory)
	loaded, err := loadPackage(".", "linux", "amd64")
	if err != nil || loaded == nil || loaded.Package.PkgPath != "hash/crc32" || loaded.Package.Types == nil || loaded.Package.TypesSizes == nil {
		t.Fatalf("actual SDK cwd/type selection failed: %v %+v", err, loaded)
	}
	for _, name := range append(append([]string(nil), loaded.Package.GoFiles...), loaded.Package.CompiledGoFiles...) {
		physical, err := sourcepath.Resolve(name)
		if err != nil || name != physical {
			t.Errorf("SDK load retained mismatched directory spelling: %q != %q (%v)", name, physical, err)
		}
	}
}

func TestSimplePackageLoadOutsideSDKRetainsInternalImportRejection(t *testing.T) {
	directory := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":  "module example.invalid/outside-sdk\n\ngo 1.24\n",
		"main.go": "package outside\nimport _ \"internal/byteorder\"\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOENV", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOPACKAGESDRIVER", "off")
	t.Chdir(directory)
	if loaded, err := loadPackage(".", runtime.GOOS, runtime.GOARCH); err == nil || loaded != nil || !strings.Contains(err.Error(), "use of internal package internal/byteorder not allowed") {
		t.Fatalf("physical working directory bypassed original internal-import boundary: %v %+v", err, loaded)
	}
}
