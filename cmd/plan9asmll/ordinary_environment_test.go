package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func TestOrdinaryPackageEnvironmentPreservesGoDefaultCGO(t *testing.T) {
	for _, target := range [][2]string{{runtime.GOOS, runtime.GOARCH}, {"js", "wasm"}} {
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
				"GOOS="+target[0], "GOARCH="+target[1], "CGO_ENABLED=")
			stdout, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), "", input,
				"go", "env", "CGO_ENABLED")
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual Go default CGO: %v; %s", err, stderr)
			}
			want := strings.TrimSpace(string(stdout))
			if want != "0" && want != "1" {
				t.Fatalf("invalid Go CGO setting %q", want)
			}
			env, err := ordinaryPackageEnvironment(target[0], target[1], input)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range env {
				if key, value, _ := strings.Cut(item, "="); key == "CGO_ENABLED" {
					if value != want {
						t.Fatalf("package inventory changed: CGO_ENABLED=%s, actual Go default=%s", value, want)
					}
					return
				}
			}
			t.Fatal("actual CGO setting was not captured")
		})
	}
}

func TestOrdinaryPackageEnvironmentRetainsExplicitSelection(t *testing.T) {
	input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"CGO_ENABLED=1", "GOFLAGS=-tags=original", "GOAMD64=v3", "GOPACKAGESDRIVER=custom")
	before := append([]string(nil), input...)
	env, err := ordinaryPackageEnvironment("linux", "amd64", input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, input) {
		t.Fatal("package-load setup mutated its caller's environment")
	}
	values := make(map[string]string)
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate effective environment key %s", key)
		}
		values[key] = value
	}
	for key, expected := range map[string]string{
		"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "1",
		"GOFLAGS": "-tags=original", "GOAMD64": "v3", "GOPACKAGESDRIVER": "custom",
	} {
		if values[key] != expected {
			t.Errorf("explicit %s changed: got %q, want %q", key, values[key], expected)
		}
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(values[key]) {
			t.Errorf("missing absolute effective %s", key)
		}
	}
}

func TestOrdinaryPackageEnvironmentCreatesSelectedCacheDirectories(t *testing.T) {
	parent := t.TempDir()
	input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local")
	paths := make(map[string]string)
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE"} {
		paths[key] = filepath.Join(parent, strings.ToLower(key), "fresh")
		input = append(input, key+"="+paths[key])
	}
	env, err := ordinaryPackageEnvironment(runtime.GOOS, runtime.GOARCH, input)
	if err != nil {
		t.Fatal(err)
	}
	for key, path := range paths {
		physical, err := sourcepath.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range env {
			found = found || entry == key+"="+physical
		}
		if !found {
			t.Fatalf("selected %s path changed", key)
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Errorf("selected %s must exist before package/source capture: %v", key, err)
		}
	}
}

func TestOrdinaryPackageEnvironmentRejectsNonDirectoryCache(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOMODCACHE="+file)
	if _, err := ordinaryPackageEnvironment(runtime.GOOS, runtime.GOARCH, input); err == nil {
		t.Fatal("non-directory cache was accepted")
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "original" {
		t.Fatal("cache setup replaced caller data", err)
	}
}

func TestOrdinaryPackageEnvironmentPreservesWorkspaceAndSavedFlags(t *testing.T) {
	dir := t.TempDir()
	workspace := filepath.Join(dir, "go.work")
	goenv := filepath.Join(dir, "goenv")
	for name, source := range map[string]string{
		"go.work": "go 1.20\nuse ./module\n",
		"goenv":   "GOFLAGS=-tags=saved_profile\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "module"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module", "go.mod"),
		[]byte("module example.invalid/selection\n\ngo 1.20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	input := append(os.Environ(), "GOENV="+goenv, "GOWORK=", "GOFLAGS=", "GOTOOLCHAIN=local")
	env, err := ordinaryPackageEnvironment(runtime.GOOS, runtime.GOARCH, input)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		values[key] = value
	}
	actualWorkspace, err := filepath.EvalSymlinks(values["GOWORK"])
	wantWorkspace, wantErr := filepath.EvalSymlinks(workspace)
	if err != nil || wantErr != nil || actualWorkspace != wantWorkspace {
		t.Errorf("implicit workspace discarded: got %q; %v", values["GOWORK"], err)
	}
	physicalConfig, configErr := sourcepath.Resolve(goenv)
	if values["GOFLAGS"] != "-tags=saved_profile" || configErr != nil || values["GOENV"] != physicalConfig {
		t.Errorf("actual saved selection was not captured: GOENV=%q GOFLAGS=%q", values["GOENV"], values["GOFLAGS"])
	}
}

func TestCallerSelectionRetainsActualLoadEnvironment(t *testing.T) {
	pkg := &packages.Package{Name: "example", PkgPath: "example.invalid/p"}
	env := []string{"GOOS=linux", "GOARCH=amd64", "GOFLAGS=", "GOPACKAGESDRIVER=off"}
	want := append([]string(nil), env...)
	t.Setenv("GOFLAGS", "-overlay=unrelated.json")
	selected := captureX86CallerSelectionsInEnvironment([]*packages.Package{pkg}, "linux/amd64", env)[pkg]
	env[0] = "GOOS=windows"
	if !reflect.DeepEqual(selected.env, want) {
		t.Fatal("selection reconstructed ambient defaults or borrowed a mutable environment")
	}
}

func TestOrdinaryPackageEnvironmentRetainsDiscoveredDriver(t *testing.T) {
	dir := t.TempDir()
	name := "gopackagesdriver"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	driver := filepath.Join(dir, name)
	// Resolution must not execute this driver while resolving Go's environment.
	if err := os.WriteFile(driver, []byte("not an executable program\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	input := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOPACKAGESDRIVER=")
	env, err := ordinaryPackageEnvironment(runtime.GOOS, runtime.GOARCH, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range env {
		if item == "GOPACKAGESDRIVER="+driver {
			return
		}
	}
	t.Fatal("automatic package driver was disabled or not captured")
}
