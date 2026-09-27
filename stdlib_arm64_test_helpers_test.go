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
		t.Fatal("GOROOT not available")
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
	// These tests validate lowering and object emission, not optimizer quality.
	// Keep them at the corpus runner's O0 level: several large IR fixtures take
	// minutes each at llc's default O2 and otherwise time out the full suite.
	cmd := exec.Command(llc, "-O0", "-mtriple="+triple, "-filetype=obj", llPath, "-o", objPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := string(out)
		if llcUnsupportedTarget(s) {
			t.Fatalf("llc does not support triple %q: %s", triple, strings.TrimSpace(s))
		}
		t.Fatalf("llc failed: %v\n%s", err, s)
	}
}
