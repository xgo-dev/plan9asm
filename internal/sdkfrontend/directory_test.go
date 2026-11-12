package sdkfrontend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestWorkingDirectoryActualIdentity(t *testing.T) {
	actual := t.TempDir()
	alias := filepath.Join(t.TempDir(), "original-directory")
	sdkEnvironmentAlias(t, alias, actual)
	want, err := sourcepath.Resolve(actual)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{actual, alias, filepath.Join(alias, ".")} {
		got, err := WorkingDirectory(input)
		if err != nil || got != want {
			t.Errorf("load directory changed its physical identity: %q -> %q, want %q (%v)", input, got, want, err)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want, err = sourcepath.Resolve(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := WorkingDirectory(""); err != nil || got != want {
		t.Errorf("implicit load directory changed its actual current node: %q != %q (%v)", got, want, err)
	}
}

func TestWorkingDirectoryRejectsMissingOrNonDirectory(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "original-file")
	const contents = "original file must not be replaced\n"
	if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing")
	for _, input := range []string{file, missing} {
		if got, err := WorkingDirectory(input); err == nil || got != "" {
			t.Errorf("unbound working-directory role was accepted: %q -> %q (%v)", input, got, err)
		}
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != contents {
		t.Fatal("non-directory input changed", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("missing directory was created or substituted", err)
	}
}
