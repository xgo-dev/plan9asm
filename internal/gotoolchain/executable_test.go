package gotoolchain

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHostExecutableNames(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, name := range []string{"go", "asm", "official-reader"} {
			want := name
			if goos == "windows" {
				want += ".exe"
			}
			if got := hostExecutable(name, goos); got != want {
				t.Fatalf("%s/%s: got %q, want %q", goos, name, got, want)
			}
		}
	}
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	if HostExecutable("go") != hostExecutable("go", runtime.GOOS) {
		t.Fatal("host suffix differs")
	}
	if info, err := os.Stat(filepath.Join(root, "bin", HostExecutable("go"))); err != nil || !info.Mode().IsRegular() {
		t.Fatal("actual selected SDK driver is missing", err)
	}
}
