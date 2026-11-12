package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestX86CallerCLIActualSelectedMemberDirectoryAlias(t *testing.T) {
	pkg, file, config := x86CallerCLILoad(t, nil)
	alias := filepath.Join(t.TempDir(), "requested-package")
	ordinaryLoadDirectoryAlias(t, alias, pkg.Dir)
	requested := filepath.Join(alias, "kernel_amd64.s")
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	_, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", requested,
		plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs)
	if err != nil || loaded == nil {
		t.Fatalf("original directory alias lost its exact actual selected caller member: %v", err)
	}
	if loaded.pkg == pkg || loaded.pkg.Types == pkg.Types {
		t.Fatal("directory alias relabelled the complete independent typed source graph")
	}
	if err := loaded.verify(config.Context, plan9asm.GoAssemblerDefines("linux", "amd64"), nil); err != nil {
		t.Fatal("original request did not retain its live final source guard", err)
	}
	if loaded.member.requested != requested || loaded.member.selected == requested ||
		loaded.goPkg.SourceSelection.Assembly[requested] != nil || config.x86CallerSelections[pkg].loaded == loaded {
		t.Fatal("request spelling replaced the actual inventory key or leaked into the shared source cache")
	}
}

func TestX86CallerCLIOriginalAliasFinalSourceGuard(t *testing.T) {
	for _, mutation := range []string{"retarget-equal-bytes", "replace-alias-same-target", "replace-selected-equal-bytes"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, file, config := x86CallerCLILoad(t, nil)
			alias := filepath.Join(t.TempDir(), "requested-package")
			ordinaryLoadDirectoryAlias(t, alias, pkg.Dir)
			requested, selected := filepath.Join(alias, "kernel_amd64.s"), filepath.Join(pkg.Dir, "kernel_amd64.s")
			resolve := resolveSymFunc(pkg.PkgPath)
			sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			defines := plan9asm.GoAssemblerDefines("linux", "amd64")
			_, aliased, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", requested, defines, config, resolve, sigs)
			if err != nil {
				t.Fatal(err)
			}
			_, physical, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", selected, defines, config, resolve, sigs)
			if err != nil {
				t.Fatal(err)
			}
			if physical == aliased || physical.member == aliased.member || physical.pkg != aliased.pkg {
				t.Fatal("per-request guards were shared or the original typed graph was recopied")
			}
			other := x86CallerCLIFixture(t)
			called := false
			ctx := &assemblyMemberCallbackContext{Context: config.Context, callback: func() {
				called = true
				if mutation == "replace-selected-equal-bytes" {
					if err := os.Rename(selected, selected+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(selected, []byte(x86CallerCLIAssembly), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Rename(alias, alias+".original"); err != nil {
						t.Fatal(err)
					}
					target := pkg.Dir
					if mutation == "retarget-equal-bytes" {
						target = other
					}
					ordinaryLoadDirectoryAlias(t, alias, target)
				}
			}}
			if err := aliased.verify(ctx, defines, nil); !called || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("callback-mutated original caller request survived complete final guard: called=%v error=%v", called, err)
			}
			if mutation == "replace-selected-equal-bytes" {
				if err := physical.verify(config.Context, defines, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("equal-byte selected-file replacement retained physical caller identity: %v", err)
				}
				if err := os.Remove(selected); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(selected+".original", selected); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := physical.verify(config.Context, defines, nil); err != nil {
					t.Fatal("independent physical request borrowed a different alias lifetime", err)
				}
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(alias+".original", alias); err != nil {
					t.Fatal(err)
				}
			}
			if err := aliased.verify(config.Context, defines, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("restoring original caller alias revived old source guard: %v", err)
			}
		})
	}
}

func TestX86CallerCLIActualSelectedFinalSymlink(t *testing.T) {
	pkg, file, config := x86CallerCLILoad(t, nil)
	selected := filepath.Join(pkg.Dir, "kernel_amd64.s")
	requested := filepath.Join(t.TempDir(), "requested.s")
	if err := os.Symlink(selected, requested); err != nil {
		t.Fatal(err)
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	defines := plan9asm.GoAssemblerDefines("linux", "amd64")
	_, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64", requested, defines, config, resolve, sigs)
	if err != nil || loaded == nil {
		t.Fatalf("final alias to actual selected caller: %v", err)
	}
	if err := loaded.verify(config.Context, defines, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(requested, requested+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(selected, requested); err != nil {
		t.Fatal(err)
	}
	if err := loaded.verify(config.Context, defines, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("same-target replacement lost original final caller node identity: %v", err)
	}
}

func TestX86CallerCLIOriginalAliasFiveTargetObjects(t *testing.T) {
	directory := x86CallerCLIFixture(t)
	t.Chdir(directory)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	alias := filepath.Join(t.TempDir(), "requested-package")
	ordinaryLoadDirectoryAlias(t, alias, directory)
	requested := filepath.Join(alias, "kernel_amd64.s")
	for _, target := range []struct{ os, triple string }{
		{"linux", "x86_64-unknown-linux-gnu"}, {"linux", "x86_64-unknown-linux-musl"},
		{"darwin", "x86_64-apple-darwin"}, {"freebsd", "x86_64-unknown-freebsd"},
		{"windows", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			pkgs, err := loadPkgs(target.os, "amd64", []string{"."}, nil, "example.com/caller", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("complete actual target selection: %v", err)
			}
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			config.Context = ctx
			config.x86CallerSelections = captureX86CallerSelections(pkgs, target.os+"/amd64", nil)
			output := filepath.Join(t.TempDir(), "alias.ll")
			originalObject := filepath.Join(filepath.Dir(output), "original-go.o")
			if stdout, stderr, err := gotoolprofile.RunBounded(ctx, directory,
				append(os.Environ(), "GOOS="+target.os, "GOARCH=amd64"), "go", "tool", "asm",
				"-p", pkgs[0].PkgPath, "-o", originalObject, requested); err != nil {
				t.Fatalf("unchanged original alias Go object: %v\n%s\n%s", err, stdout, stderr)
			}
			if err := compileOne(pkgs[0], plan9asm.ArchAMD64, target.os, "amd64", target.triple,
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: requested, OutLL: output}, false, config); err != nil {
				t.Fatal("original caller request did not reach LLVM22 object", err)
			}
			for _, object := range []string{originalObject, strings.TrimSuffix(output, ".ll") + ".o"} {
				info, err := os.Stat(object)
				if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
					t.Fatalf("missing actual original/LLVM22 object: %v", err)
				}
			}
		})
	}
}
