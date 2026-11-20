package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneCallerLateSourceGuardDoesNotPublish(t *testing.T) {
	pkg, _, config := x86CallerCLILoad(t, nil)
	output := filepath.Join(pkg.Dir, "published.ll")
	const retained = "previous verified output\n"
	if err := os.WriteFile(output, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	ctx := &continuationOutputCallbackContext{Context: context.Background(), directory: pkg.Dir, basename: filepath.Base(output), callback: func() {
		called = true
		if err := os.WriteFile(filepath.Join(pkg.Dir, "caller.go"), []byte(x86CallerCLISource+"\n// late source replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	config.Context = ctx
	err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: filepath.Join(pkg.Dir, "kernel_amd64.s"), OutLL: output}, false, config)
	if !called || err == nil {
		t.Fatalf("actual caller guard did not observe late source change: called=%v error=%v", called, err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("ordinary changed source was mislabeled cancellation: %v", err)
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != retained {
		t.Fatalf("late caller rejection overwrote retained public output: %v", err)
	}
}

func TestCompileOneARM64TailLateSourceGuardDoesNotPublish(t *testing.T) {
	directory := arm64ABI0TailCLIFixture(t)
	t.Chdir(directory)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	selected, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
	if err != nil || len(selected) != 1 {
		t.Fatalf("actual complete Go selection: %v", err)
	}
	output := filepath.Join(directory, "retained.ll")
	const retained = "previous verified ARM64 output\n"
	if err := os.WriteFile(output, []byte(retained), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	ctx := &continuationOutputCallbackContext{Context: arm64PrivateCLIContext(t), directory: directory, basename: filepath.Base(output), callback: func() {
		called = true
		if err := os.WriteFile(filepath.Join(directory, "p.go"), []byte("package p\nfunc Slots(value uint64) (out uint64)\n// late replacement\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	config := compileConfig{Context: ctx, x86CallerSelections: captureX86CallerSelections(selected, "linux/arm64", nil)}
	err = compileOne(selected[0], plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: selected[0].PkgPath, AsmFile: filepath.Join(directory, "p_arm64.s"), OutLL: output}, false, config)
	if !called || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("late ARM64 source guard not reached: called=%v error=%v", called, err)
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != retained {
		t.Fatalf("late ARM64 guard changed public output: %q %v", data, err)
	}
}

func TestCompileOneFixedLocalLateOwnerGuardDoesNotPublish(t *testing.T) {
	for _, change := range []string{"source", "owned-directory"} {
		t.Run(change, func(t *testing.T) {
			private := t.TempDir()
			t.Setenv("TMPDIR", private)
			pkg, input, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
			output := filepath.Join(t.TempDir(), "retained.ll")
			const retained = "previous verified fixed-local output\n"
			if err := os.WriteFile(output, []byte(retained), 0600); err != nil {
				t.Fatal(err)
			}
			called := false
			config.Context = &continuationOutputCallbackContext{Context: config.Context,
				directory: filepath.Dir(output), basename: filepath.Base(output), callback: func() {
					called = true
					if change == "source" {
						if err := os.WriteFile(filepath.Join(pkg.Dir, "value.go"), []byte("package fixedlocal\nfunc Value(a, b, c, d uint64) uint64\n// late replacement\n"), 0600); err != nil {
							t.Fatal(err)
						}
						return
					}
					owned, err := filepath.Glob(filepath.Join(private, "plan9asm-go-frame-object-*"))
					if err != nil || len(owned) != 1 {
						t.Fatalf("actual frame artifact owner missing: %v %v", owned, err)
					}
					if err := os.Rename(owned[0], owned[0]+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(owned[0], 0700); err != nil {
						t.Fatal(err)
					}
				}}
			// IR-only still consumes the complete original native frame objects;
			// the external LLVM object axis is covered by the original class.
			config.Enabled = false
			err := compileOne(pkg, plan9asm.ArchAMD64, "linux", "amd64", "x86_64-unknown-linux-gnu",
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
			if !called || err == nil {
				t.Fatalf("late fixed-local owner guard not reached: called=%v error=%v", called, err)
			}
			if change == "owned-directory" && !strings.Contains(err.Error(), "artifact directory") {
				t.Fatalf("actual owner cleanup cause lost: %v", err)
			}
			if data, err := os.ReadFile(output); err != nil || string(data) != retained {
				t.Fatalf("late source/owner failure changed public output: %q %v", data, err)
			}
		})
	}
}
