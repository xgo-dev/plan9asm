package sdkfrontend

import (
	"context"
	"errors"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func selectedFixture(t *testing.T, name string) *Package {
	t.Helper()
	folder := t.TempDir()
	file := filepath.Join(folder, "value.go")
	if err := os.WriteFile(file, []byte("package sample\nvar Value uint64\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &Package{ID: name, Name: "sample", Path: name, Dir: folder,
		GoFiles: []string{file}, CompiledGoFiles: []string{file}, Types: types.NewPackage(name, "sample"),
		Sizes: types.SizesFor("gc", "amd64"), Imports: make(map[string]*Package)}
}

func TestSelectionRetainsCompleteOriginalSourceAndTypes(t *testing.T) {
	pkg, dependency := selectedFixture(t, "sample"), selectedFixture(t, "dependency")
	pkg.Imports[dependency.Path] = dependency
	selection := CaptureSelection(pkg, "linux/amd64", []string{"GOPACKAGESDRIVER=off"}, nil)
	if err := Check(pkg, selection, "linux/amd64"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func() func(){
		func() func() {
			old := pkg.Types
			pkg.Types = types.NewPackage(pkg.Path, pkg.Name)
			return func() { pkg.Types = old }
		},
		func() func() {
			old := dependency.Types
			dependency.Types = types.NewPackage(dependency.Path, dependency.Name)
			return func() { dependency.Types = old }
		},
		func() func() {
			old := dependency.CompiledGoFiles
			dependency.CompiledGoFiles = nil
			return func() { dependency.CompiledGoFiles = old }
		},
		func() func() {
			file := dependency.GoFiles[0]
			old, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, append(old, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			return func() {
				if err := os.WriteFile(file, old, 0600); err != nil {
					t.Fatal(err)
				}
			}
		},
	} {
		restore := mutate()
		if err := Check(pkg, selection, "linux/amd64"); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatal("changed original load/source was accepted", err)
		}
		restore()
	}
}

func TestSDKReloadRequiresBoundedActualLoadContext(t *testing.T) {
	pkg := selectedFixture(t, "sample")
	selected := CaptureSelection(pkg, "linux/amd64", nil, nil)
	loader := func(context.Context, string, []string) (*Package, error) {
		t.Fatal("unbound or cancelled reload invoked a loader")
		return nil, nil
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), cancelled} {
		actual, selection, release, err := Reload(ctx, "go", pkg, selected, loader)
		if actual != nil || selection != nil || release != nil || err == nil {
			t.Fatalf("invalid context produced a source load: %v", err)
		}
		if ctx == cancelled && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation became a missing-proof classification", err)
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	if _, _, _, err := Reload(ctx, "go", pkg, nil, loader); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("missing load selection did not fail before command execution", err)
	}
}

func TestSharedSDKSourceClosesInReverseOrderAndRetainsErrors(t *testing.T) {
	first, second := errors.New("numerical"), errors.New("data")
	var order []string
	source := &Source{}
	source.identity = source
	for _, row := range []struct {
		name string
		err  error
	}{{"CPU", nil}, {"data", second}, {"literal", nil}, {"numerical", first}} {
		row := row
		source.cleanup = append(source.cleanup, func() error {
			order = append(order, row.name)
			return row.err
		})
	}
	err := source.Close()
	if !errors.Is(err, first) || !errors.Is(err, second) || !reflect.DeepEqual(order, []string{"numerical", "literal", "data", "CPU"}) {
		t.Fatalf("lost owner/close order or authoritative error: %v, %v", order, err)
	}
	if err := source.Close(); err != nil || len(order) != 4 {
		t.Fatal("closed handles were invoked twice", err)
	}
}
