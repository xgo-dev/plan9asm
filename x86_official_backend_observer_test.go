package plan9asm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The overlay only adds an owned test. All original SDK implementation and
// test files remain present and byte-identical. This observes Go's encoder;
// it grants no translator, object-decoder or native-entry permission.
func x86OriginalGoBackendOutput(t *testing.T, fixture, testRoot string) []byte {
	t.Helper()
	fixture, err := filepath.Abs(fixture)
	if err != nil || !strings.HasSuffix(fixture, "_test.go") {
		t.Fatal("invalid owned SDK backend fixture", fixture, err)
	}
	sdk := runtime.GOROOT()
	directory := filepath.Join(sdk, "src", "cmd", "internal", "obj", "x86")
	snapshot := func() map[string][32]byte {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		result := map[string][32]byte{}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
				data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				result[entry.Name()] = sha256.Sum256(data)
			}
		}
		return result
	}
	before := snapshot()
	virtual := filepath.Join(directory, "plan9asm_"+filepath.Base(fixture))
	if _, err := os.Stat(virtual); !os.IsNotExist(err) {
		t.Fatal("SDK overlay must add a new test, never replace an existing file", virtual, err)
	}
	dir := t.TempDir()
	overlay := filepath.Join(dir, "overlay.json")
	data, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{virtual: fixture}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, data, 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(sdk, "bin", "go"), "test", "-p=1",
		"-overlay="+overlay, "cmd/internal/obj/x86", "-run", "^"+regexp.QuoteMeta(testRoot)+"$",
		"-count=1", "-timeout=90s", "-json")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOROOT="+sdk, "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
		"GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	output, commandErr := runtimeOracleCombinedOutput(ctx, command)
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("original SDK source inventory changed during the test-only overlay")
	}
	for name, digest := range before {
		if after[name] != digest {
			t.Fatal("original SDK source bytes changed during the test-only overlay", name)
		}
	}
	if commandErr != nil || ctx.Err() != nil {
		t.Fatalf("actual Go backend source observer failed: %v / %v\n%s", commandErr, ctx.Err(), output)
	}
	fixtureBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ACTUAL_GO_BACKEND_SOURCE originalSDKGoFiles=%d fixtureSHA=%x outputSHA=%x",
		len(before), sha256.Sum256(fixtureBytes), sha256.Sum256(output))
	return output
}
