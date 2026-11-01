package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

func TestContinuationActualSelectedOutsideAliasReferenceClosure(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	for _, name := range []string{"unselected-Go", "unselected-ASM", "header"} {
		t.Run(name, func(t *testing.T) {
			_, selected := continuationPackage(t, continuationGo, continuationAsm)
			directory := filepath.Dir(selected)
			pkgs, err := loadPkgs("linux", "amd64", []string{"."}, nil, "example.com/continuations", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("actual full original compiler selection: %v", err)
			}
			pkg := pkgs[0]
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, continuationAsm)
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			defines := plan9asm.GoAssemblerDefines("linux", "amd64")
			groups, _, err := inferX86TailGroups(pkg, file, selected, "amd64", resolve, sigs, defines, config)
			if err != nil || len(groups) != 1 {
				t.Fatalf("actual selected baseline did not identify the private table: %v %+v", err, groups)
			}
			reference, source := "reference_windows.go", "//go:build windows\n\npackage p\nfunc external() { step() }\n"
			if name == "unselected-ASM" {
				reference, source = "_reference.s", "TEXT ·external(SB),$0-0\nJMP ·step(SB)\n"
			}
			if name == "header" {
				reference, source = "reference.h", "// external reference to step\n"
			}
			if err := os.WriteFile(filepath.Join(directory, reference), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			groups, _, err = inferX86TailGroups(pkg, file, selected, "amd64", resolve, sigs, defines, config)
			if err != nil || len(groups) != 0 {
				t.Fatalf("physical-directory sibling reference was not rejected: %v %+v", err, groups)
			}
			requested := filepath.Join(t.TempDir(), "requested_amd64.s")
			if err := os.Symlink(selected, requested); err != nil {
				t.Fatal(err)
			}
			groups, _, err = inferX86TailGroups(pkg, file, requested, "amd64", resolve, sigs, defines, config)
			if err != nil || len(groups) != 0 {
				t.Fatalf("original alias changed the whole selected-package reference closure: %v %+v", err, groups)
			}
		})
	}
}

func continuationObservedSource(t *testing.T, extra map[string]string) (*continuationReferenceSource, compileConfig) {
	return continuationObservedSourceInContext(t, extra, context.Background())
}

func continuationObservedSourceInContext(t *testing.T, extra map[string]string, ctx context.Context) (*continuationReferenceSource, compileConfig) {
	t.Helper()
	pkg, selected := continuationPackageWithSources(t, continuationGo, continuationAsm, extra)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, continuationAsm)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	config := compileConfig{Context: ctx, x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	groups, source, err := inferX86TailGroups(pkg, file, selected, "amd64", resolve, sigs, plan9asm.GoAssemblerDefines("linux", "amd64"), config)
	if err != nil || len(groups) != 1 || source == nil {
		t.Fatalf("complete unchanged reference source: %v %+v", err, groups)
	}
	for _, record := range source.files {
		if record.data != nil {
			t.Fatal("privacy query retained a second full plaintext tape after publication")
		}
	}
	return source, config
}

type continuationFinalCallbackContext struct {
	context.Context
	callback func()
}

func (ctx *continuationFinalCallbackContext) Err() error {
	if ctx.callback != nil {
		pcs := make([]uintptr, 32)
		frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
		for {
			frame, more := frames.Next()
			if strings.HasSuffix(frame.Function, "(*continuationReferenceSource).verify.func1") {
				callback := ctx.callback
				ctx.callback = nil
				callback()
				break
			}
			if !more {
				break
			}
		}
	}
	return ctx.Context.Err()
}

func TestContinuationReferenceSourceFinalOriginalCallbackIsGuarded(t *testing.T) {
	ctx := &continuationFinalCallbackContext{Context: context.Background()}
	source, _ := continuationObservedSourceInContext(t, nil, ctx)
	called := false
	ctx.callback = func() {
		called = true
		if err := os.WriteFile(filepath.Join(source.directory, "_late.h"), []byte("// step\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.verify(context.Background(), plan9asm.GoAssemblerDefines("linux", "amd64"), nil); !called || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("last original-context callback escaped final inventory validation: called=%v error=%v", called, err)
	}
}

func TestContinuationReferenceSourceOriginalCancellationIsPermanent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source, _ := continuationObservedSourceInContext(t, nil, ctx)
	cancel()
	if err := source.verify(context.Background(), plan9asm.GoAssemblerDefines("linux", "amd64"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement verification context erased original cancellation: %v", err)
	}
	if err := source.verify(context.Background(), plan9asm.GoAssemblerDefines("linux", "amd64"), nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("rejected original context revived its reference source: %v", err)
	}
	var missing *continuationReferenceSource
	if err := missing.verify(context.Background(), nil, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("nil source: %v", err)
	}
}

func TestContinuationActualSelectedFinalSymlinkUsesPackageDirectory(t *testing.T) {
	pkg, selected := continuationPackage(t, continuationGo, continuationAsm)
	other := filepath.Join(pkg.Dir, "native-source")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(other, "original.s")
	if err := os.Rename(selected, physical); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, selected); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "reference.go"), []byte("package p\nfunc use() { step() }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadPkgs("linux", "amd64", []string{"."}, nil, pkg.PkgPath, true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual selected final-symlink graph: %v", err)
	}
	pkg = pkgs[0]
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, continuationAsm)
	if err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	groups, source, err := inferX86TailGroups(pkg, file, selected, "amd64", resolve, sigs, plan9asm.GoAssemblerDefines("linux", "amd64"), config)
	if err != nil || len(groups) != 1 || source == nil || source.directory == other {
		t.Fatalf("selected final target borrowed an unrelated directory's reference role: %v %+v", err, groups)
	}
}

func TestContinuationSeparatelyNamedPhysicalSiblingRemainsReference(t *testing.T) {
	for _, alias := range []string{"symlink", "hardlink"} {
		t.Run(alias, func(t *testing.T) {
			pkg, selected := continuationPackage(t, continuationGo, continuationAsm)
			other := filepath.Join(pkg.Dir, "_separately_named.s")
			var err error
			if alias == "symlink" {
				err = os.Symlink(selected, other)
			} else {
				err = os.Link(selected, other)
			}
			if err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, continuationAsm)
			if err != nil {
				t.Fatal(err)
			}
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			groups, source, err := inferX86TailGroups(pkg, file, selected, "amd64", resolve, sigs, plan9asm.GoAssemblerDefines("linux", "amd64"), config)
			if err != nil || len(groups) != 0 || source != nil {
				t.Fatalf("physical equality erased a separately named sibling reference: %v %+v", err, groups)
			}
		})
	}
}

func TestContinuationReferenceSourceLateChangesArePermanent(t *testing.T) {
	for _, change := range []string{"new-Go", "new-s", "new-S", "new-h", "bytes", "same-byte-node", "selected-directory"} {
		t.Run(change, func(t *testing.T) {
			source, config := continuationObservedSource(t, map[string]string{"reference_windows.go": "//go:build windows\n\npackage p\n// no helper reference\n"})
			filename := filepath.Join(source.directory, "reference_windows.go")
			var restore func()
			called := false
			if change == "selected-directory" {
				// Go's t.Chdir pins the previous directory until cleanup. On
				// Windows that handle would prevent the actual rename mutation.
				// The fixture already owns restoring its original working directory.
				if err := os.Chdir(filepath.Dir(source.directory)); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chdir(source.directory); err != nil {
						t.Error("restore selected fixture directory", err)
					}
				})
			}
			ctx := &assemblyMemberCallbackContext{Context: config.Context, callback: func() {
				called = true
				switch change {
				case "new-Go", "new-s", "new-S", "new-h":
					extension := map[string]string{"new-Go": ".go", "new-s": ".s", "new-S": ".S", "new-h": ".h"}[change]
					filename = filepath.Join(source.directory, "_late"+extension)
					if err := os.WriteFile(filename, []byte("// step\n"), 0600); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if err := os.Remove(filename); err != nil {
							t.Fatal(err)
						}
					}
				case "bytes":
					original, err := os.ReadFile(filename)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filename, []byte("//go:build windows\n\npackage p\nfunc external() { step() }\n"), 0600); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if err := os.WriteFile(filename, original, 0600); err != nil {
							t.Fatal(err)
						}
					}
				case "same-byte-node":
					original, err := os.ReadFile(filename)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(filename, filename+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filename, original, 0600); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if err := os.Remove(filename); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(filename+".original", filename); err != nil {
							t.Fatal(err)
						}
					}
				case "selected-directory":
					if err := os.Rename(source.directory, source.directory+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(source.directory, 0700); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if err := os.Remove(source.directory); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(source.directory+".original", source.directory); err != nil {
							t.Fatal(err)
						}
					}
				}
			}}
			if err := source.verify(ctx, plan9asm.GoAssemblerDefines("linux", "amd64"), nil); !called || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("late reference mutation survived complete source guard: called=%v error=%v", called, err)
			}
			restore()
			if err := source.verify(config.Context, plan9asm.GoAssemblerDefines("linux", "amd64"), nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("restoring a changed reference closure revived it: %v", err)
			}
		})
	}
}
