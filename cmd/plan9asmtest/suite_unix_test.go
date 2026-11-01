//go:build unix

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":        "module example.org/runnerfixture\n\ngo 1.20\n",
		"value.go":      "package fixture\nfunc value() int { return 7 }\n",
		"value_test.go": source,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func readReport(t *testing.T, out string) suiteReport {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report suiteReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestActualGoSuiteIncludesAllRootsSeedsAndInstrumentation(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	dir := fixture(t, `package fixture
import (
    "fmt"
    "testing"
)
func TestAlpha(t *testing.T) {
    t.Parallel()
    t.Run("parallel", func(t *testing.T) { t.Parallel(); if value() != 7 { t.Fatal("value") } })
}
func TestBeta(t *testing.T) {
    t.Run("duplicate", func(t *testing.T) {})
    t.Run("duplicate", func(t *testing.T) {})
    t.Run("path/leaf", func(t *testing.T) {})
}
func TestExistingSkip(t *testing.T) { t.Skip("existing explicit Go skip") }
func Example() { fmt.Println(value()); /* Output: 7 */ }
func FuzzSeeds(f *testing.F) {
    f.Add(1)
    f.Add(2)
    f.Fuzz(func(t *testing.T, input int) { if value() != 7 { t.Fatal(input) } })
}
func BenchmarkNotRun(b *testing.B) { b.Fatal("benchmarks must not run in ordinary go test") }
`)
	// A build-selected test must appear in both the actual list and execution.
	selected := "//go:build runnerfixture\n\npackage fixture\nimport \"testing\"\nfunc TestSelected(t *testing.T) {}\n"
	if err := os.WriteFile(filepath.Join(dir, "selected_test.go"), []byte(selected), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "artifacts")
	// Cold race-instrumented standard-library compilation under the required
	// Linux diagnostic emulator is distinct from execution. Keep it bounded,
	// but do not confuse a short fixture build budget with a broken decoder.
	err := runSuite(context.Background(), config{Go: "go", Dir: dir, Package: ".", Out: out, Shards: 5, Timeout: 4 * time.Minute, Flags: []string{"-race", "-covermode=atomic", "-coverprofile=actual.cover", "-tags=runnerfixture", "-p=1"}})
	if err != nil {
		listing, _ := os.ReadFile(filepath.Join(out, "inventory.stdout"))
		t.Fatalf("actual instrumented suite: %v\n%s", err, listing)
	}
	report := readReport(t, out)
	if report.Status != "passed" || len(report.Names) != 6 || report.RootPassed != 5 || report.RootSkipped != 1 || report.RootFailed != 0 || report.RootMissing != 0 || report.ChildPassed != 6 || len(report.Benchmarks) != 1 {
		t.Fatalf("incomplete or relabeled actual inventory: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(dir, "actual.cover")); err != nil {
		t.Fatalf("actual race/coverage profile absent: %v", err)
	}
	for _, shard := range report.Shards {
		if len(shard.Names) != 0 && (!strings.Contains(strings.Join(shard.Command, " "), "-race") || shard.Status != "passed") {
			t.Fatalf("lost instrumentation or execution: %+v", shard)
		}
	}
}

func TestActualGoFailureIsRetainedAndRemainingShardsRun(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	dir := fixture(t, "package fixture\nimport \"testing\"\nfunc TestFails(t *testing.T) { t.Fatal(\"actual failure\") }\nfunc TestRemaining(t *testing.T) {}\n")
	out := filepath.Join(t.TempDir(), "artifacts")
	err := runSuite(context.Background(), config{Go: "go", Dir: dir, Package: ".", Out: out, Shards: 5, Timeout: 30 * time.Second})
	if err == nil {
		t.Fatal("actual Go child failure was promoted")
	}
	report := readReport(t, out)
	if report.Status != "failed" || report.RootFailed != 1 || report.RootPassed != 1 || report.RootMissing != 0 {
		t.Fatalf("failure lost or remaining shard omitted: %+v", report)
	}
}

func TestActualGoTimeoutCannotPassAndRetainsPlan(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	dir := fixture(t, "package fixture\nimport \"testing\"\nfunc TestHang(t *testing.T) { select {} }\n")
	out := filepath.Join(t.TempDir(), "artifacts")
	// Both commands have the same real wall deadline. Allow the actual Go
	// inventory to compile/link before proving the hung test is canceled.
	err := runSuite(context.Background(), config{Go: "go", Dir: dir, Package: ".", Out: out, Shards: 1, Timeout: 30 * time.Second})
	if err == nil {
		t.Fatal("timed out Go child was promoted")
	}
	report := readReport(t, out)
	if len(report.Names) != 1 || report.Names[0] != "TestHang" || report.Status != "failed" || report.Shards[0].Status != "failed" || report.Shards[0].Outcomes["TestHang"] != "run" || !strings.Contains(report.Error, "deadline exceeded") {
		t.Fatalf("timeout lost original plan: %+v", report)
	}
}

func TestExpiredDeadlineCannotInventAnInventory(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	out := filepath.Join(t.TempDir(), "artifacts")
	err := runSuite(context.Background(), config{Go: "go", Dir: t.TempDir(), Package: ".", Out: out, Shards: 1, Timeout: time.Nanosecond})
	if err == nil {
		t.Fatal("expired command was promoted")
	}
	report := readReport(t, out)
	if report.Status != "failed" || len(report.Names) != 0 || len(report.Shards) != 0 || !strings.Contains(report.Error, "deadline exceeded") {
		t.Fatalf("expired command invented coverage: %+v", report)
	}
}

func TestHiddenFiltersAndOutputReuseFailBeforeExecutingGo(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "artifacts")
	t.Setenv("GOFLAGS", "-run=TestSubset")
	if err := runSuite(context.Background(), config{Go: "missing-go", Dir: dir, Package: ".", Out: out, Shards: 1, Timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "GOFLAGS") {
		t.Fatalf("inherited filter was not rejected before Go: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("invalid flags touched artifacts: %v", err)
	}
	t.Setenv("GOFLAGS", "")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := runSuite(context.Background(), config{Go: "go", Dir: dir, Package: ".", Out: out, Shards: 1, Timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "must be new") {
		t.Fatalf("existing artifacts could be overwritten: %v", err)
	}
}

func TestCaptureOutputBoundCancelsAndPreservesFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	file, err := os.Create(filepath.Join(t.TempDir(), "bounded"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	bound := &boundedOutput{Remaining: 3, Cancel: cancel}
	if n, err := (outputWriter{file, bound}).Write([]byte("four")); err == nil || n != 0 || ctx.Err() == nil || bound.Err == nil {
		t.Fatalf("output bound silently discarded data: n=%d err=%v context=%v", n, err, ctx.Err())
	}
}

func TestOwnedCommandKillsDescendantsAfterExitAndTimeout(t *testing.T) {
	const helperEnv = "PLAN9ASM_TEST_PARTITION_CHILD"
	if mode := os.Getenv(helperEnv); mode != "" {
		if mode == "writer" {
			_ = os.WriteFile("ready", []byte("ready"), 0600)
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat("release"); err == nil {
					_ = os.WriteFile("late-write", []byte("unreleased child"), 0600)
					os.Exit(0)
				}
				time.Sleep(5 * time.Millisecond)
			}
			os.Exit(0)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestOwnedCommandKillsDescendantsAfterExitAndTimeout$")
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, helperEnv+"=") {
				child.Env = append(child.Env, entry)
			}
		}
		child.Env = append(child.Env, helperEnv+"=writer")
		if err := child.Start(); err != nil {
			os.Exit(19)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat("ready"); err == nil {
				if mode == "timeout" {
					time.Sleep(5 * time.Second)
				}
				os.Exit(0)
			}
			time.Sleep(5 * time.Millisecond)
		}
		os.Exit(20)
	}
	for _, mode := range []string{"success", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(helperEnv, mode)
			dir := t.TempDir()
			timeout := time.Second
			if mode == "success" {
				// A race-instrumented helper spends one second in its normal
				// exit grace period. That is not a command cancellation.
				timeout = 5 * time.Second
			}
			_, err := captureCommand(context.Background(), timeout, dir, os.Args[0], []string{"-test.run=^TestOwnedCommandKillsDescendantsAfterExitAndTimeout$"}, filepath.Join(dir, "helper"))
			if (mode == "timeout") != (err != nil) {
				t.Fatalf("lost command outcome: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "ready")); err != nil {
				t.Fatalf("owned descendant never started: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(150 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(dir, "late-write")); !os.IsNotExist(err) {
				t.Fatalf("descendant survived owned process completion: %v", err)
			}
		})
	}
}
