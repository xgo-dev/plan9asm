//go:build unix

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parallelFixtureCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "plan9asmtest")
	stem := filepath.Join(t.TempDir(), "build")
	_, err := captureCommand(context.Background(), 2*time.Minute, ".", "go",
		[]string{"build", "-p=1", "-o", binary, "."}, stem)
	if err != nil {
		stderr, _ := os.ReadFile(stem + ".stderr")
		t.Fatalf("build actual CLI: %v\n%s", err, stderr)
	}
	return binary
}

func TestParallelCLIActualGoInventoryAndCoverage(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	binary := parallelFixtureCLI(t)
	dir := fixture(t, `package fixture

import (
    "fmt"
    "os"
    "testing"
    "time"
)

func peer(t *testing.T, own, other string) {
    t.Helper()
    if err := os.WriteFile(own, []byte("started"), 0600); err != nil {
        t.Fatal(err)
    }
    deadline := time.Now().Add(10 * time.Second)
    for time.Now().Before(deadline) {
        if _, err := os.Stat(other); err == nil {
            return
        }
        time.Sleep(10 * time.Millisecond)
    }
    t.Fatal("the other actual Go shard did not execute concurrently")
}

// Their first eight SHA-256 bytes have different remainders modulo two.
func TestWorkerOne(t *testing.T) { peer(t, "one", "two") }
func TestAlpha(t *testing.T) {
    t.Run("peer", func(t *testing.T) { peer(t, "two", "one") })
}
func TestExistingSkip(t *testing.T) { t.Skip("existing explicit source skip") }
func Example() { fmt.Println(value()); /* Output: 7 */ }
func FuzzSeeds(f *testing.F) {
    f.Add(1)
    f.Add(2)
    f.Fuzz(func(t *testing.T, input int) {
        if value() != 7 { t.Fatal(input) }
    })
}
func BenchmarkNotRun(b *testing.B) { b.Fatal("ordinary suite ran a benchmark") }
`)
	out := filepath.Join(t.TempDir(), "report")
	stem := filepath.Join(t.TempDir(), "cli")
	_, err := captureCommand(context.Background(), 4*time.Minute, ".", binary,
		[]string{"-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--",
			"-race", "-covermode=atomic", "-coverprofile=actual.cover", "-p=1"}, stem)
	if err != nil {
		stderr, _ := os.ReadFile(stem + ".stderr")
		t.Fatalf("actual bounded parallel CLI: %v\n%s", err, stderr)
	}
	report := readReport(t, out)
	if report.Status != "passed" || len(report.Names) != 5 || report.RootPassed != 4 ||
		report.RootSkipped != 1 || report.RootFailed != 0 || report.RootMissing != 0 ||
		report.ChildPassed != 3 || report.ChildFailed != 0 || report.ChildMissing != 0 ||
		len(report.Benchmarks) != 1 {
		t.Fatalf("parallel execution changed the exhaustive denominator: %+v", report)
	}
	for _, shard := range report.Shards {
		command := strings.Join(shard.Command, " ")
		if shard.Status != "passed" || !strings.Contains(command, "-race") ||
			!strings.Contains(command, "-timeout=2m0s") || !strings.Contains(command, "-count=1") {
			t.Fatalf("parallelism changed execution flags: %+v", shard)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Workers int `json:"workers"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Workers != 2 {
		t.Fatalf("actual worker limit was not retained: workers=%d err=%v", metadata.Workers, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "actual.cover")); err != nil {
		t.Fatalf("complete actual parallel coverage absent: %v", err)
	}
}

func TestParallelCLIFailureKeepsRemainingRootsAndNoMergedCoverage(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	binary := parallelFixtureCLI(t)
	dir := fixture(t, `package fixture

import "testing"

func TestWorkerOne(t *testing.T) { t.Fatal("original source failure") }
func TestAlpha(t *testing.T) { t.Run("remaining", func(t *testing.T) {}) }
`)
	out := filepath.Join(t.TempDir(), "report")
	stem := filepath.Join(t.TempDir(), "cli")
	_, err := captureCommand(context.Background(), 3*time.Minute, ".", binary,
		[]string{"-dir", dir, "-out", out, "-shards=8", "-workers=2", "-timeout=2m", "--",
			"-coverprofile=must-not-exist.cover", "-p=1"}, stem)
	if err == nil {
		t.Fatal("actual failed child became success")
	}
	report := readReport(t, out)
	if report.Status != "failed" || report.RootFailed != 1 || report.RootPassed != 1 ||
		report.RootMissing != 0 || report.ChildPassed != 1 || report.ChildMissing != 0 {
		t.Fatalf("parallel failure canceled or hid other roots: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(dir, "must-not-exist.cover")); !os.IsNotExist(err) {
		t.Fatalf("failed suite published merged coverage: %v", err)
	}
}
