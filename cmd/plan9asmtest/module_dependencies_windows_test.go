package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func windowsModuleDependencyFixture(t *testing.T) (config, string) {
	t.Helper()
	t.Setenv("GOFLAGS", "-tags=byollvm")
	t.Setenv("GOENV", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": moduleLLVMFixtureGoMod(t, "example.org/windows-llvm-consumer"),
		"consumer.go": `package consumer
import "github.com/xgo-dev/llvm"
func Context() llvm.Context { return llvm.NewContext() }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0600); err != nil {
		t.Fatal(err)
	}
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		entries, _ := os.ReadDir(out)
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".stderr") &&
				!strings.Contains(entry.Name(), "-node-version.") &&
				!strings.Contains(entry.Name(), "-llvm-config") &&
				!strings.Contains(entry.Name(), "-llvm-shared-files.") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(out, entry.Name()))
			if err == nil && len(data) > 0 {
				t.Logf("%s: %q", entry.Name(), data)
			}
		}
	})
	cfg := config{Go: driver, Dir: dir, Module: true, Flags: []string{"-tags=byollvm"}, Timeout: 2 * time.Minute}
	return cfg, out
}

func TestWindowsModuleActualLLVMDependencyScope(t *testing.T) {
	cfg, out := windowsModuleDependencyFixture(t)
	before, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "before"))
	if err != nil {
		t.Fatal("actual Windows module dependency capture", err)
	}
	after, err := captureCIScope(context.Background(), cfg, filepath.Join(out, "after"))
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("unchanged Windows source/tool/loader scopes differ", err)
	}
	if before.Environment["GOFLAGS"] != "-tags=byollvm" || before.Tools["llvm-loaded"] == "" {
		t.Fatal("actual inherited selection or loaded DLL identity is missing")
	}
	if err := verifyModuleDependencyArtifacts(out, moduleReport{Scope: before}); err != nil {
		t.Fatal("actual Windows dependency artifact readback", err)
	}
	path := filepath.Join(out, "before-llvm-loaded-library.json")
	var loaded moduleLoadedLibrary
	if err := ciReadJSON(path, &loaded); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual Go LLVM binding loaded %s", loaded.Path)
	loaded.Path = filepath.Join(out, "foreign.dll")
	if err := ciWriteJSON(path, loaded); err != nil {
		t.Fatal(err)
	}
	if err := verifyModuleDependencyArtifacts(out, moduleReport{Scope: before}); err == nil {
		t.Fatal("foreign loaded-library path became valid evidence")
	}
}

func TestWindowsModuleActualLLVMLoader(t *testing.T) {
	// Observe this independent boundary even if an earlier environment or
	// Node observation prevents the complete-scope test from reaching it.
	cfg, out := windowsModuleDependencyFixture(t)
	binary, err := resolveCIConfigExecutable()
	if err != nil {
		t.Fatal(err)
	}
	stem := filepath.Join(out, "actual")
	version, err := moduleDependencyCommand(context.Background(), cfg, stem+"-llvm-configversion", binary, "--version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "22.") {
		t.Fatal("actual LLVM 22 configuration required", err)
	}
	data, err := moduleDependencyCommand(context.Background(), cfg, stem+"-llvm-shared-files", binary, "--libfiles", "--link-shared")
	if err != nil {
		t.Fatal(err)
	}
	libraries, err := moduleSharedLibraries(data)
	if err != nil {
		t.Fatal(err)
	}
	origins := map[string]string{}
	if err := captureModuleLLVMBinding(context.Background(), cfg, stem, libraries, origins); err != nil {
		t.Fatal("actual Windows Go LLVM loader", err)
	}
	if origins["llvm-loaded"] == "" {
		t.Fatal("selected Go LLVM consumer did not execute its loader query")
	}
}
