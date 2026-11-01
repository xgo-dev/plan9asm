package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestARM64ABI0TailActualSelectedMemberDirectoryAlias(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	directory, err := sourcepath.Resolve(arm64ABI0TailCLIFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "requested-package")
	ordinaryLoadDirectoryAlias(t, alias, directory)
	t.Chdir(directory)
	pkgs, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("complete original module selection: %v %+v", err, pkgs)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/arm64", nil)
	input := filepath.Join(alias, "p_arm64.s")
	expanded, err := readAsmSource(input, asmSourceRoot(pkgs[0], input))
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadARM64ABI0TailSource(pkgs[0], input, expanded, "linux/arm64", nil, config)
	if err != nil {
		t.Fatal("requested directory alias lost its exact actual selected assembly member", err)
	}
	if source.asm != input || source.actual == pkgs[0] || source.actual.Types == pkgs[0].Types {
		t.Fatal("original request or complete independent typed graph was relabelled")
	}
	if err := source.verify(config.Context, nil, nil); err != nil {
		t.Fatal("same original requested member did not retain its live identity", err)
	}
	output := filepath.Join(t.TempDir(), "alias.ll")
	if err := compileOne(pkgs[0], plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
		t.Fatal("original alias request did not reach the actual LLVM22 object", err)
	}
	info, err := os.Stat(strings.TrimSuffix(output, ".ll") + ".o")
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatalf("missing complete original-alias LLVM22 object: %v", err)
	}
}

type assemblyMemberCallbackContext struct {
	context.Context
	callback func()
}

func (ctx *assemblyMemberCallbackContext) Err() error {
	if callback := ctx.callback; callback != nil {
		ctx.callback = nil
		callback()
	}
	return ctx.Context.Err()
}

func TestARM64ABI0TailOriginalAliasPostGuard(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	directory, err := sourcepath.Resolve(arm64ABI0TailCLIFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "requested-package")
	ordinaryLoadDirectoryAlias(t, alias, directory)
	t.Chdir(directory)
	pkgs, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("complete actual selection: %v", err)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/arm64", nil)
	input := filepath.Join(alias, "p_arm64.s")
	expanded, err := readAsmSource(input, asmSourceRoot(pkgs[0], input))
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadARM64ABI0TailSource(pkgs[0], input, expanded, "linux/arm64", nil, config)
	if err != nil {
		t.Fatal(err)
	}
	other := arm64ABI0TailCLIFixture(t) // Complete, byte-identical but unselected package.
	called := false
	ctx := &assemblyMemberCallbackContext{Context: config.Context, callback: func() {
		called = true
		if err := os.Rename(alias, alias+".original"); err != nil {
			t.Fatal(err)
		}
		ordinaryLoadDirectoryAlias(t, alias, other)
	}}
	if err := source.verify(ctx, nil, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || !called {
		t.Fatalf("callback-retargeted original request survived complete final source guard: called=%v error=%v", called, err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(alias+".original", alias); err != nil {
		t.Fatal(err)
	}
	if err := source.verify(config.Context, nil, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("restoring original request revived rejected source: %v", err)
	}
}

func TestARM64ABI0TailActualSelectedFinalSymlink(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	directory := arm64ABI0TailCLIFixture(t)
	input := filepath.Join(directory, "p_arm64.s")
	if err := os.Rename(input, input+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input+".original", input); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	pkgs, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("actual compiler final-symlink selection: %v", err)
	}
	config, err := resolveCompileConfig(true, "", true, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.Context = arm64PrivateCLIContext(t)
	config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/arm64", nil)
	expanded, err := readAsmSource(input, asmSourceRoot(pkgs[0], input))
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadARM64ABI0TailSource(pkgs[0], input, expanded, "linux/arm64", nil, config)
	if err != nil {
		t.Fatal("selected final symlink lost its original source contract", err)
	}
	if err := source.verify(config.Context, nil, nil); err != nil {
		t.Fatal(err)
	}
}
