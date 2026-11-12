//go:build !windows

package plan9asm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestX87IA32StaticELFRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "original")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(source, x87IA32SyntheticELF(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := x87IA32StaticExecutable(alias); err == nil {
		t.Fatal("symlink executable was accepted")
	}
}
