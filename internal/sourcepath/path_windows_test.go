//go:build windows

package sourcepath

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveWindowsJunctionIdentity(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	child := filepath.Join(actual, "nested")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "source.s"), []byte("TEXT ·Probe(SB),$0-0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", alias, actual)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("create required native directory junction: %v\n%s", err, output)
	}
	linkInfo, err := Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := Lstat(actual)
	if err != nil || os.SameFile(linkInfo, targetInfo) {
		t.Fatalf("identity capture followed the final junction: %v", err)
	}
	for _, mode := range []string{"0", "1"} {
		t.Run("winsymlink="+mode, func(t *testing.T) {
			t.Setenv("GODEBUG", "winsymlink="+mode+",winreadlinkvolume=1")
			for _, suffix := range []string{".", "nested", "nested/source.s"} {
				t.Run(suffix, func(t *testing.T) {
					want, err := Resolve(filepath.Join(actual, filepath.FromSlash(suffix)))
					if err != nil {
						t.Fatal(err)
					}
					got, err := Resolve(filepath.Join(alias, filepath.FromSlash(suffix)))
					if err != nil || got != want || !filepath.IsAbs(got) {
						t.Fatalf("junction identity differs: got=%q want=%q error=%v", got, want, err)
					}
					before, err := os.Stat(filepath.Join(alias, filepath.FromSlash(suffix)))
					if err != nil {
						t.Fatal(err)
					}
					after, err := os.Stat(got)
					if err != nil || !os.SameFile(before, after) {
						t.Fatalf("resolved a different actual file: %v", err)
					}
				})
			}
			if _, err := Resolve(filepath.Join(alias, "missing")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing junction descendant lost its actual cause: %v", err)
			}
		})
	}
}

func TestResolveWindowsLongPathAndHandleRelease(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, strings.Repeat("long-", 35), "child", "source.s")
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if _, err := Lstat(name); err != nil {
			t.Fatal("long-path identity capture", err)
		}
		resolved, err := Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(resolved)
		if err != nil || string(data) != "source" {
			t.Fatalf("long resolved path cannot reopen its source: %v", err)
		}
	}
	// Rename and remove immediately: resolution must not retain an open file.
	renamed := name + ".renamed"
	if err := os.Rename(name, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsDOSPathRetainsOnlyNativeAbsoluteRoutes(t *testing.T) {
	for native, want := range map[string]string{
		`\\?\C:\source\file.s`:        `C:\source\file.s`,
		`\\?\C:\`:                     `C:\`,
		`\\?\UNC\server\share\file.s`: `\\server\share\file.s`,
	} {
		if got, err := windowsDOSPath(native); err != nil || got != want {
			t.Fatalf("normalized native route %q: got=%q want=%q error=%v", native, got, want, err)
		}
	}
	for _, native := range []string{
		"", `C:\source`, `\\.\C:\source`, `\\?\C:source`,
		`\\?\Volume{unbound}\source`, `\\?\C:\source\..\file.s`,
		"\\\\?\\C:\\source\x00hidden", "\\\\?\\C:\\source\nline",
	} {
		if got, err := windowsDOSPath(native); err == nil || got != "" {
			t.Fatalf("unknown/noncanonical native route accepted: %q => %q (%v)", native, got, err)
		}
	}
}
