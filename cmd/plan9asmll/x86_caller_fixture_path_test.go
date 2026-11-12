package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestX86CallerCLIFixtureCapturesCanonicalSelectionBeforeWrites(t *testing.T) {
	owned, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(owned, "physical")
	if err := os.Mkdir(physical, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(owned, "alias")
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	t.Setenv("GOTMPDIR", alias)
	t.Run("actual selection", func(t *testing.T) {
		pkg, file, config := x86CallerCLILoad(t, map[string]string{
			"other_amd64.s": "TEXT ·other(SB),4,$0-0\nRET\n",
		})
		canonical, err := filepath.EvalSymlinks(pkg.Dir)
		if err != nil || pkg.Dir != canonical {
			t.Fatalf("package was selected through a noncanonical fixture path: %s, %v", pkg.Dir, err)
		}
		for _, filenames := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.OtherFiles} {
			for _, filename := range filenames {
				resolved, err := filepath.EvalSymlinks(filename)
				if err != nil || filename != resolved {
					t.Fatalf("actual selected source changed path identity: %s, %v", filename, err)
				}
			}
		}
		resolve := resolveSymFunc(pkg.PkgPath)
		sigs, _, err := sigsForAsmFile(pkg, file, resolve, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		selected := filepath.Join(pkg.Dir, "kernel_amd64.s")
		if _, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
			selected, plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs); err != nil || loaded == nil {
			t.Fatalf("canonical actual selection did not close: %v", err)
		}
		relative, err := filepath.Rel(physical, selected)
		if err != nil || !filepath.IsLocal(relative) {
			t.Fatalf("fixture source escaped its owned physical parent: %s, %v", relative, err)
		}
		if _, loaded, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
			filepath.Join(alias, relative), plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs); err != nil || loaded == nil || loaded.member == nil {
			t.Fatalf("exact alias was not independently observed against the actual selection: %v", err)
		}
		unselected := filepath.Join(t.TempDir(), "kernel_amd64.s")
		if err := os.WriteFile(unselected, []byte(x86CallerCLIAssembly), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := bindX86CallerRegions(pkg, file, "linux/amd64", "amd64",
			unselected, plan9asm.GoAssemblerDefines("linux", "amd64"), config, resolve, sigs); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("unselected equal-byte file acquired actual selection authority: %v", err)
		}
	})
}
