package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func TestOrdinaryPackageLoadSDKWorkingDirectoryIdentity(t *testing.T) {
	actualRoot, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "original-sdk")
	ordinaryLoadDirectoryAlias(t, alias, actualRoot)
	for _, profile := range []string{"effective-defaults", "saved-config"} {
		t.Run(profile, func(t *testing.T) {
			for key, value := range map[string]string{
				"GOROOT": alias, "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
				"GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "", "GOPACKAGESDRIVER": "off",
			} {
				t.Setenv(key, value)
			}
			for _, key := range []string{"CGO_ENABLED", "GOAMD64", "GO386"} {
				t.Setenv(key, "")
				if err := os.Unsetenv(key); err != nil {
					t.Fatal(err)
				}
			}
			if profile == "saved-config" {
				config := filepath.Join(t.TempDir(), "original-goenv")
				if err := os.WriteFile(config, []byte("GOPROXY=https://original-config.invalid,direct\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("GOENV", config)
			}
			directory := filepath.Join(alias, "src", "hash", "crc32")
			if runtime.GOOS == "windows" {
				directory = filepath.ToSlash(strings.ToLower(filepath.VolumeName(directory)) + strings.TrimPrefix(directory, filepath.VolumeName(directory)))
			}
			t.Chdir(directory)
			t.Setenv("PWD", directory)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			keys := []string{"CGO_ENABLED", "GOAMD64", "GO386", "GOENV", "GOPROXY", "GOFLAGS"}
			before, diagnostics, err := gotoolprofile.RunBounded(ctx, directory, os.Environ(), "go", append([]string{"env", "-json"}, keys...)...)
			if err != nil || len(diagnostics) != 0 {
				t.Fatalf("original compiler defaults: %v; %s", err, diagnostics)
			}
			original, err := packages.Load(&packages.Config{Context: ctx, Dir: directory, Env: os.Environ(),
				Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedTypesSizes}, ".")
			if err != nil || len(original) != 1 || len(original[0].Errors) != 0 || original[0].PkgPath != "hash/crc32" {
				t.Fatalf("unmodified original SDK internal-import selection failed: %v %+v", err, original)
			}
			selected, environment, err := loadPkgsInEnvironment("linux", "amd64", []string{"."}, nil, "", true, false, nil)
			if err != nil || len(selected) != 1 || selected[0].PkgPath != original[0].PkgPath || selected[0].Types == nil || selected[0].TypesSizes == nil {
				t.Fatalf("physical SDK environment lost its original cwd/package/type role: %v %+v", err, selected)
			}
			if len(selected[0].GoFiles) != len(original[0].GoFiles) || len(selected[0].CompiledGoFiles) != len(original[0].CompiledGoFiles) || len(selected[0].Imports) != len(original[0].Imports) {
				t.Fatal("canonical directory changed the complete original compiler source/import inventory")
			}
			for index, inventory := range [][]string{original[0].GoFiles, original[0].CompiledGoFiles} {
				actual := selected[0].GoFiles
				if index == 1 {
					actual = selected[0].CompiledGoFiles
				}
				if !reflect.DeepEqual(ordinaryLoadSourceIdentity(t, inventory), ordinaryLoadSourceIdentity(t, actual)) {
					t.Fatal("canonical load changed complete original source identities/bytes")
				}
			}
			for path, imported := range original[0].Imports {
				actual := selected[0].Imports[path]
				if imported.Types == nil || actual == nil || actual.Types == nil || actual.PkgPath != imported.PkgPath || actual.Types.Path() != imported.Types.Path() {
					t.Fatalf("canonical load changed original compiler import/type identity: %s", path)
				}
			}
			for _, name := range append(append([]string(nil), selected[0].GoFiles...), selected[0].CompiledGoFiles...) {
				physical, err := sourcepath.Resolve(name)
				if err != nil || physical != name {
					t.Errorf("selected original SDK source kept an unbound alias: selected=%q physical=%q error=%v", name, physical, err)
				}
			}
			after, diagnostics, err := gotoolprofile.RunBounded(ctx, "", environment, "go", append([]string{"env", "-json"}, keys...)...)
			var oldProfile, newProfile map[string]string
			if err != nil || len(diagnostics) != 0 || json.Unmarshal(before, &oldProfile) != nil || json.Unmarshal(after, &newProfile) != nil {
				t.Fatalf("actual canonical compiler defaults: %v; %s", err, diagnostics)
			}
			for _, key := range keys {
				if key == "GOENV" && oldProfile[key] != "" && oldProfile[key] != "off" {
					oldProfile[key], err = sourcepath.Resolve(oldProfile[key])
					if err != nil {
						t.Fatal(err)
					}
				}
				if oldProfile[key] != newProfile[key] {
					t.Errorf("working-directory identity changed original default/config %s: %q != %q", key, oldProfile[key], newProfile[key])
				}
			}
		})
	}
}

func ordinaryLoadSourceIdentity(t *testing.T, names []string) map[string][32]byte {
	t.Helper()
	result := make(map[string][32]byte, len(names))
	for _, name := range names {
		physical, err := sourcepath.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(physical)
		if err != nil {
			t.Fatal(err)
		}
		result[physical] = sha256.Sum256(data)
	}
	return result
}

func TestOrdinaryPackageLoadOutsideSDKRetainsInternalImportRejection(t *testing.T) {
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
	original, err := packages.Load(&packages.Config{Dir: directory, Env: os.Environ(),
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedTypesSizes}, ".")
	if err != nil || len(original) != 1 || len(original[0].Errors) == 0 || !strings.Contains(original[0].Errors[0].Msg, "use of internal package internal/byteorder not allowed") {
		t.Fatalf("stock compiler internal-package negative is absent: %v %+v", err, original)
	}
	if pkgs, _, err := loadPkgsInEnvironment(runtime.GOOS, runtime.GOARCH, []string{"."}, nil, "", true, false, nil); err == nil || len(pkgs) != 0 || !strings.Contains(err.Error(), "package loading error") {
		t.Fatalf("physical working directory bypassed stock internal-package rejection: %v %+v", err, pkgs)
	}
}
