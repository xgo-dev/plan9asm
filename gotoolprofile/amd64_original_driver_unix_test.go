//go:build unix

package gotoolprofile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAMD64OriginalObservationFixtureCanonicalDriver(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(binary, filepath.Join(dir, "go")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	request := amd64OriginalObservationFixture(t, "numeric")
	physical, err := filepath.EvalSymlinks(request.GoBinary)
	if err != nil || physical != request.GoBinary {
		t.Fatalf("fixture supplied a redirected driver to the strict actual-object factory: %v", err)
	}
}
