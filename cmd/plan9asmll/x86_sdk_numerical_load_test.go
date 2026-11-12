package main

import (
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func TestX86SDKNumericalReloadPhysicalSourceIdentity(t *testing.T) {
	root, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"value.go": "package sample\nfunc Value() uint64\n",
		"value.s":  "TEXT ·Value(SB),4,$0-8\nMOVQ $1,ret+0(FP)\nRET\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(t.TempDir(), "source-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	// Metadata unit only: neither projection supplies a live SDK capture,
	// type certificate, numerical owner or translation permission.
	selection := func(directory string) *packages.Package {
		return &packages.Package{
			ID: "sample", PkgPath: "sample", Name: "sample", Dir: directory,
			Types:           types.NewPackage("sample", "sample"),
			GoFiles:         []string{filepath.Join(directory, "value.go")},
			CompiledGoFiles: []string{filepath.Join(directory, "value.go")},
			OtherFiles:      []string{filepath.Join(directory, "value.s")},
		}
	}
	physical, logical := selection(root), selection(alias)
	want, err := x86SDKLoadGraph(physical)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := x86SDKLoadGraph(logical)
	if err != nil || !reflect.DeepEqual(actual, want) {
		t.Fatalf("same physical SDK files acquired different source identities: %v", err)
	}
	wantFiles, err := x86SDKSelectedSourceHashes(physical)
	if err != nil {
		t.Fatal(err)
	}
	actualFiles, err := x86SDKSelectedSourceHashes(logical)
	if err != nil || !reflect.DeepEqual(actualFiles, wantFiles) {
		t.Fatalf("same source bytes acquired different physical keys: %v", err)
	}
	if logical.Dir != alias || logical.GoFiles[0] != filepath.Join(alias, "value.go") {
		t.Fatal("identity projection rewrote the original package selection")
	}
	foreign := filepath.Join(t.TempDir(), "value.go")
	data, err := os.ReadFile(physical.GoFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, data, 0600); err != nil {
		t.Fatal(err)
	}
	logical.CompiledGoFiles[0] = foreign
	if changed, err := x86SDKLoadGraph(logical); err == nil && reflect.DeepEqual(changed, want) {
		t.Fatal("equal-byte foreign file borrowed the captured source identity")
	}
	if changed, err := x86SDKSelectedSourceHashes(logical); err == nil && reflect.DeepEqual(changed, wantFiles) {
		t.Fatal("equal-byte foreign file borrowed the original hash inventory")
	}
}
