package gotoolprofile

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestRunBoundedSuccessAndFailure(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not found")
	}
	stdout, stderr, err := RunBounded(context.Background(), "", nil, goBin, "version")
	if err != nil {
		t.Fatalf("RunBounded(go version) failed: %v (stderr=%q)", err, stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(stdout)), "go version") {
		t.Fatalf("unexpected go version output: %q", stdout)
	}

	if _, _, err := RunBounded(context.Background(), "", nil, goBin, "nonexistent-subcommand-xyz"); err == nil {
		t.Fatal("expected failure for invalid go subcommand")
	}
	if _, _, err := RunBounded(nil, "", nil, goBin, "version"); err == nil {
		t.Fatal("expected error for nil context")
	}
	if _, _, err := RunBounded(context.Background(), "", nil, ""); err == nil {
		t.Fatal("expected error for empty binary name")
	}
}
