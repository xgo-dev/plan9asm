//go:build windows

package gotoolprofile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestCPPRegularSourceWindowsJunctionBoundaries(t *testing.T) {
	t.Setenv("GODEBUG", "winsymlink=1,winreadlinkvolume=1")
	base := t.TempDir()
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	for _, dir := range []string{root, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "source.h"), []byte("#define VALUE 7\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	junction := func(alias, target string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "cmd", "/c", "mklink", "/J", alias, target)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("create required actual junction: %v\n%s", err, output)
		}
	}
	alias := filepath.Join(base, "alias")
	junction(alias, root)
	want, err := sourcepath.Resolve(filepath.Join(root, "source.h"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := CPPRegularSource(alias, "source.h"); err != nil || got != want {
		t.Fatalf("root alias lost its actual regular source: got=%q want=%q error=%v", got, want, err)
	}
	junction(filepath.Join(root, "redirected"), outside)
	if got, err := CPPRegularSource(alias, "redirected/source.h"); err == nil || got != "" {
		t.Fatalf("nested junction bypassed original source containment: %q (%v)", got, err)
	}
}
