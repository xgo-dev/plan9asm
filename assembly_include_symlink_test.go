//go:build !windows

package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadGoAssemblySourceRejectsSymlinkIncludeOutsideRoot(t *testing.T) {
	sandbox := t.TempDir()
	sourceRoot := filepath.Join(sandbox, "module")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(sandbox, "outside.h")
	if err := os.WriteFile(outside, []byte("#define OUTSIDE 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sourceRoot, "escape.h")); err != nil {
		t.Fatal(err)
	}
	asm := filepath.Join(sourceRoot, "entry_amd64.s")
	if err := os.WriteFile(asm, []byte("#include \"escape.h\"\nTEXT ·entry(SB),$0-0\nRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadGoAssemblySource(asm, sourceRoot)
	if err == nil || !strings.Contains(err.Error(), "escapes source root") {
		t.Fatalf("ReadGoAssemblySource symlink escape error = %v, want source-root rejection", err)
	}
}
