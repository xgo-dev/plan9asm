//go:build !llgo
// +build !llgo

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const arm64LinuxGNUTriple = "aarch64-unknown-linux-gnu"

func testGOROOT(t *testing.T) string {
	t.Helper()
	if goroot := os.Getenv("GOROOT"); goroot != "" {
		return goroot
	}
	goroot, err := testGoEnv("GOROOT")
	if err != nil || goroot == "" {
		t.Skip("GOROOT not available")
	}
	return goroot
}

func testGoEnv(key string) (string, error) {
	out, err := exec.Command("go", "env", key).CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func compileLLVMToObject(t *testing.T, llc, triple, llName, objName, ll string) {
	t.Helper()
	tmp := t.TempDir()
	llPath := filepath.Join(tmp, llName)
	objPath := filepath.Join(tmp, objName)
	if err := os.WriteFile(llPath, []byte(ll), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=obj", llPath, "-o", objPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := string(out)
		if llcUnsupportedTarget(s) {
			t.Fatalf("llc does not support triple %q: %s", triple, strings.TrimSpace(s))
		}
		t.Fatalf("llc failed: %v\n%s", err, s)
	}
}
