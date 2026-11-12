package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

type continuationOutputCallbackContext struct {
	context.Context
	directory, basename string
	callback            func()
}

func (ctx *continuationOutputCallbackContext) Err() error {
	if ctx.callback != nil {
		// Observe either the historical direct output or the repaired owned
		// stage, without arming on an assumed callback count or source line.
		if data, err := os.ReadFile(filepath.Join(ctx.directory, ctx.basename)); err == nil && strings.Contains(string(data), "define ") {
			callback := ctx.callback
			ctx.callback = nil
			callback()
		}
		for _, directory := range []string{ctx.directory, filepath.Dir(ctx.directory)} {
			entries, err := os.ReadDir(directory)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".plan9asm-output-") {
					continue
				}
				if info, err := os.Stat(filepath.Join(directory, entry.Name(), ctx.basename)); err == nil && info.Mode().IsRegular() {
					if ctx.callback == nil {
						break
					}
					callback := ctx.callback
					ctx.callback = nil
					callback()
					break
				}
			}
		}
	}
	return ctx.Context.Err()
}

func TestCompileOneContinuationLateReferenceDoesNotPublish(t *testing.T) {
	for _, change := range []string{"new-reference", "retarget-original-alias"} {
		t.Run(change, func(t *testing.T) {
			pkg, selected := continuationPackage(t, continuationGo, continuationAsm)
			alias := filepath.Join(t.TempDir(), "requested-package")
			ordinaryLoadDirectoryAlias(t, alias, pkg.Dir)
			requested := filepath.Join(alias, filepath.Base(selected))
			output := filepath.Join(pkg.Dir, "published.ll")
			const retained = "previous verified user output\n"
			if err := os.WriteFile(output, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			ctx := &continuationOutputCallbackContext{Context: context.Background(), directory: pkg.Dir, basename: filepath.Base(output)}
			ctx.callback = func() {
				called = true
				if change == "new-reference" {
					if err := os.WriteFile(filepath.Join(pkg.Dir, "_late.s"), []byte("TEXT ·external(SB),$0-0\nJMP ·step(SB)\n"), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					other := t.TempDir()
					if err := os.WriteFile(filepath.Join(other, "p_amd64.s"), []byte(continuationAsm), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(alias, alias+".original"); err != nil {
						t.Fatal(err)
					}
					ordinaryLoadDirectoryAlias(t, alias, other)
				}
			}
			config := compileConfig{Context: ctx, x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: requested, OutLL: output}, false, config)
			if !called || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("late actual reference closure was published: called=%v error=%v", called, err)
			}
			if data, err := os.ReadFile(output); err != nil || string(data) != retained {
				t.Fatalf("failed final source guard overwrote retained output: %v", err)
			}
			entries, err := os.ReadDir(filepath.Dir(pkg.Dir))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".plan9asm-output-") {
					t.Fatal("owned failed output stage was not released")
				}
			}
		})
	}
}

func TestCompileOneContinuationPublishesInsideSelectedOwner(t *testing.T) {
	pkg, selected := continuationPackage(t, continuationGo, continuationAsm)
	config := compileConfig{x86CallerSelections: captureX86CallerSelections([]*packages.Package{pkg}, "linux/amd64", nil)}
	output := filepath.Join(pkg.Dir, "inside-owner.ll")
	if err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: selected, OutLL: output}, false, config); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil || strings.Count(string(data), "define ") != 2 || !strings.Contains(string(data), "blockaddress") {
		t.Fatalf("complete verified owner publication: %v", err)
	}
}
