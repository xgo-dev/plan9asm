package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestGoAMD64FrameSourceCloseRejectsReplacedOwnedDirectory(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	request.Environment = append(request.Environment, "TMPDIR="+temporary, "GOTMPDIR="+temporary)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	owned := source.owned
	original, err := sourcepath.Lstat(owned)
	if err != nil {
		t.Fatal(err)
	}
	// Every path here belongs to t.TempDir. The replacement models a different
	// owner at the same spelling; Close must not recursively remove that owner.
	moved := filepath.Join(t.TempDir(), "original-artifacts")
	if err := os.Rename(owned, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	replacement, err := sourcepath.Lstat(owned)
	if err != nil || os.SameFile(original, replacement) {
		t.Fatalf("fixture did not replace directory identity: %v", err)
	}
	canary := filepath.Join(owned, "replacement-owner.txt")
	if err := os.WriteFile(canary, []byte("not a factory artifact\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Errorf("Close did not reject changed directory identity: %v", err)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("Close removed replacement owner's file: %v", err)
	}
	if source.ready {
		t.Error("failed cleanup retained ready observation")
	}
	// Restore only our known original directory for the fixture's registered
	// cleanup. RemoveAll is limited to this exact t.TempDir-owned replacement.
	if err := os.RemoveAll(owned); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, owned); err != nil {
		t.Fatal(err)
	}
}

func TestGoAMD64FrameSourceRequestTemporaryOwnership(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	parentTemporary := t.TempDir()
	requestTemporary := t.TempDir()
	canonicalTemporary, err := filepath.EvalSymlinks(requestTemporary)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", parentTemporary)
	// Like exec.Cmd, the supplied environment's last occurrence wins. Neither
	// the inherited parent TMPDIR nor the earlier supplied value is ownership.
	request.Environment = append(request.Environment,
		"TMPDIR="+parentTemporary, "TMPDIR="+requestTemporary,
		"GOTMPDIR="+requestTemporary)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	if filepath.Dir(source.owned) != canonicalTemporary {
		t.Fatalf("factory artifacts are outside request TMPDIR: got parent %q, want %q", filepath.Dir(source.owned), canonicalTemporary)
	}
	if err := source.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	owned := source.owned
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("Close retained factory artifacts: %v", err)
	}
	for _, name := range []string{parentTemporary, requestTemporary, request.Directory} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("Close removed a caller-owned directory: %v", err)
		}
	}
}

func TestGoAMD64FrameSourceRepeatedEnvironmentActualValues(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR"} {
		var expected string
		for _, item := range request.Environment {
			name, value, _ := strings.Cut(item, "=")
			if name == key {
				expected = value
			}
		}
		if !filepath.IsAbs(expected) {
			t.Fatalf("fixture lacks owned %s", key)
		}
		request.Environment = append(request.Environment, key+"="+t.TempDir(), key+"="+expected)
	}
	// Target and routing settings are deliberately overridden, not accepted
	// from a different validation view of a repeated key.
	request.Environment = append(request.Environment, "GOOS=windows", "GOOS=darwin", "GOARCH=386", "GOARCH=arm64")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOTMPDIR"} {
		var expected string
		for _, item := range source.request.Environment {
			name, value, _ := strings.Cut(item, "=")
			if name == key {
				expected = value
			}
		}
		if source.env[key] != expected {
			t.Fatalf("actual %s differs from effective supplied value: %q != %q", key, source.env[key], expected)
		}
	}
	if source.env["GOOS"] != "linux" || source.env["GOARCH"] != "amd64" {
		t.Fatalf("repeated target keys changed actual target: %v", source.env)
	}
}

func TestGoAMD64FrameSourceOwnedIdentityRejectsRedirection(t *testing.T) {
	for _, kind := range []string{"equal-byte directory", "symlink", "missing"} {
		t.Run(kind, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			owned := source.owned
			moved := filepath.Join(t.TempDir(), "original-artifacts")
			if err := os.Rename(owned, moved); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(owned); err != nil {
					t.Error(err)
				}
				if err := os.Rename(moved, owned); err != nil {
					t.Error(err)
				}
			})
			switch kind {
			case "equal-byte directory":
				if err := os.Mkdir(owned, 0700); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(moved)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(moved, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(owned, entry.Name()), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "symlink":
				if err := os.Symlink(moved, owned); err != nil {
					t.Fatal(err)
				}
			}
			if err := source.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
				t.Fatalf("changed owned directory retained observation: %v", err)
			}
			if err := source.Close(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Close did not reject changed ownership: %v", err)
			}
			if kind != "missing" {
				if _, err := os.Lstat(owned); err != nil {
					t.Fatalf("Close removed a replacement directory or link: %v", err)
				}
			}
			if _, err := os.Stat(filepath.Join(moved, request.AssemblyFile+".o")); err != nil {
				t.Fatalf("Close searched for or removed moved original artifacts: %v", err)
			}
		})
	}
}

func TestGoAMD64FrameSourceCanonicalRootAndExplicitToolPaths(t *testing.T) {
	t.Run("resolved package root is fixed", func(t *testing.T) {
		pkg, request := goAMD64FrameSourceFixture(t)
		original, err := filepath.EvalSymlinks(request.Directory)
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(t.TempDir(), "package-alias")
		if err := os.Symlink(original, alias); err != nil {
			t.Fatal(err)
		}
		request.Directory = alias
		source := requireGoAMD64FrameCapture(t, pkg, request)
		if source.request.Directory != original {
			t.Fatalf("capture did not bind actual canonical root: %q", source.request.Directory)
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), alias); err != nil {
			t.Fatal(err)
		}
		if err := source.Verify(context.Background()); err != nil {
			t.Fatalf("unconsumed caller alias changed fixed canonical source: %v", err)
		}
	})
	t.Run("Go binary symlink is not a source identity", func(t *testing.T) {
		pkg, request := goAMD64FrameSourceFixture(t)
		alias := filepath.Join(t.TempDir(), "go")
		if err := os.Symlink(request.GoBinary, alias); err != nil {
			t.Fatal(err)
		}
		request.GoBinary = alias
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
		if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("indirected driver produced an observation: %v", err)
		}
	})
}

func TestGoAMD64FrameSourceRepeatedForbiddenEnvironmentStaysContext(t *testing.T) {
	for _, key := range []string{"GOFLAGS", "GOEXPERIMENT", "GOPACKAGESDRIVER"} {
		t.Run(key, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			// Capture conservatively rejects any requested unsupported mapping,
			// including one shadowed by a later empty occurrence.
			request.Environment = append(request.Environment, key+"=unbound", key+"=")
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unsupported duplicate %s mapping was accepted: %v", key, err)
			}
		})
	}
}
