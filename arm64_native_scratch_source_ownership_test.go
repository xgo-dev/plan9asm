package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func arm64ScratchCaptureAliasedTemporary(t *testing.T, goos string) (context.Context, *GoARM64ScratchSource) {
	t.Helper()
	pkg, request := arm64ScratchActualSourceFixture(t, goos)
	parentTemporary := t.TempDir()
	physicalTemporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "request-temporary")
	if err := os.Symlink(physicalTemporary, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", parentTemporary)
	request.Environment = append(request.Environment,
		"TMPDIR="+parentTemporary, "TMPDIR="+alias, "GOTMPDIR="+alias)
	ctx, cancel := runtimeOracleStageContext(t)
	t.Cleanup(cancel)
	source, err := CaptureGoARM64ScratchSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if filepath.Dir(source.owned) != physicalTemporary {
		t.Fatalf("factory artifacts are outside physical request TMPDIR: %q", source.owned)
	}
	if source.settings["TMPDIR"] != alias {
		t.Fatal("canonical artifact identity changed the effective command environment")
	}
	if info, err := os.Lstat(source.owned); err != nil || !info.IsDir() || !os.SameFile(info, source.ownedInfo) {
		t.Fatalf("canonical factory directory lost its created identity: %v", err)
	}
	return ctx, source
}

func TestARM64NativeScratchRequestTemporaryOwnership(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			ctx, source := arm64ScratchCaptureAliasedTemporary(t, goos)
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			owned := source.owned
			parent := filepath.Dir(owned)
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(owned); !os.IsNotExist(err) {
				t.Fatalf("Close retained factory artifacts: %v", err)
			}
			for _, name := range []string{parent, source.request.Directory, source.settings["TMPDIR"]} {
				if _, err := os.Stat(name); err != nil {
					t.Fatalf("Close removed caller-owned source/temporary input: %v", err)
				}
			}
		})
	}
}

func TestARM64NativeScratchOwnedIdentityRejectsRedirection(t *testing.T) {
	for _, kind := range []string{"replacement directory", "symlink", "missing"} {
		t.Run(kind, func(t *testing.T) {
			ctx, source := arm64ScratchCaptureAliasedTemporary(t, "linux")
			owned := source.owned
			moved := filepath.Join(t.TempDir(), "original-artifacts")
			if err := os.Rename(owned, moved); err != nil {
				t.Fatal(err)
			}
			// Restore this fixture's original identity before its factory
			// cleanup runs. Every replacement is inside our temporary root.
			t.Cleanup(func() {
				if err := os.RemoveAll(owned); err != nil {
					t.Error(err)
				}
				if err := os.Rename(moved, owned); err != nil {
					t.Error(err)
				}
			})
			switch kind {
			case "replacement directory":
				if err := os.Mkdir(owned, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(owned, "other-owner"), []byte("retain me"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(moved, owned); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
				t.Fatalf("changed owned identity retained observation: %v", err)
			}
			if err := source.Close(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Close accepted an unowned replacement: %v", err)
			}
			if kind != "missing" {
				if _, err := os.Lstat(owned); err != nil {
					t.Fatalf("Close removed a replacement directory/link: %v", err)
				}
			}
			if _, err := os.Stat(filepath.Join(moved, "symabis-1")); err != nil {
				t.Fatalf("Close removed moved original artifacts: %v", err)
			}
		})
	}
}
