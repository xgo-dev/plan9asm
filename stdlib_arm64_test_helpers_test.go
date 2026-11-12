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
	goroot, err := testGoEnv(t, "GOROOT")
	if err != nil || goroot == "" {
		t.Fatalf("GOROOT not available: %v\n%s", err, goroot)
	}
	return goroot
}

func testGoEnv(t *testing.T, key string) (string, error) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "env", key)
	out, err := runtimeOracleCombinedOutput(ctx, command)
	return strings.TrimSpace(string(out)), err
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
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, llc, "-O0", "-mtriple="+triple, "-filetype=obj", llPath, "-o", objPath)
	out, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil {
		s := string(out)
		if llcUnsupportedTarget(s) {
			t.Fatalf("llc does not support triple %q: %s", triple, strings.TrimSpace(s))
		}
		t.Fatalf("llc failed: %v\n%s", err, s)
	}
}
