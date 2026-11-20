//go:build unix

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The control directory is outside the immutable observed module. Only real
// unfiltered Go test bodies publish ready; go list/-list cannot open a barrier.
func moduleWorkerFixture(t *testing.T, failing bool) (config, string) {
	t.Helper()
	moduleFixtureEnvironment(t)
	dir, controls := moduleFixture(t, false), t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		pkg := filepath.Join(dir, "parallel", name)
		if err := os.MkdirAll(pkg, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkg, "value.go"), []byte("package parallel\nfunc Value() int { return 7 }\n"), 0600); err != nil {
			t.Fatal(err)
		}
		source := fmt.Sprintf(`package parallel
import ("flag"; "fmt"; "os"; "path/filepath"; "testing"; "time")
func TestMain(m *testing.M) {
    flag.Parse()
    if flag.Lookup("test.list").Value.String() == "" { fmt.Println("FULL_PACKAGE_MAIN_%s") }
    os.Exit(m.Run())
}
func TestHeld(t *testing.T) {
    directory, name := %q, %q
    if err := os.WriteFile(filepath.Join(directory, "pid-"+name), []byte(fmt.Sprint(os.Getpid())), 0600); err != nil { t.Fatal(err) }
    active := filepath.Join(directory, "active-"+name)
    if err := os.WriteFile(active, []byte(name), 0600); err != nil { t.Fatal(err) }
    defer os.Remove(active)
    ready := filepath.Join(directory, "ready-"+name)
    if err := os.WriteFile(ready+".pending", []byte(name), 0600); err != nil { t.Fatal(err) }
    if err := os.Rename(ready+".pending", ready); err != nil { t.Fatal(err) }
    deadline := time.Now().Add(2*time.Minute)
    for {
        if _, err := os.Stat(filepath.Join(directory, "release-"+name)); err == nil { break }
        if time.Now().After(deadline) { t.Fatal("actual package barrier expired") }
        time.Sleep(10*time.Millisecond)
    }
    if %t && name == "b" { t.Fatal("retained actual package failure") }
}
func ExampleValue() { fmt.Println(Value()); /* Output: 7 */ }
func FuzzValue(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, n int) { if Value()!=7 { t.Fatal(n) } }) }
func BenchmarkNever(b *testing.B) { b.Fatal("benchmark executed") }
`, name, controls, name, failing)
		if err := os.WriteFile(filepath.Join(pkg, "value_test.go"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return config{Go: "go", Dir: dir, Package: ".", Out: filepath.Join(t.TempDir(), "owner-0002"),
		Module: true, ModuleOwner: 2, CIOwner: -1, Shards: 2, Workers: 2, Timeout: 3 * time.Minute,
		Flags: []string{"-p=1"}}, controls
}

func moduleWorkerWaitReady(t *testing.T, ctx context.Context, controls, name string, done <-chan error) {
	t.Helper()
	for {
		data, err := os.ReadFile(filepath.Join(controls, "ready-"+name))
		if err == nil {
			if string(data) != name {
				t.Fatal("partial or foreign ready publication", name, string(data))
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual package did not become ready", name, ctx.Err())
		case err := <-done:
			t.Fatal("module completed before actual package ready", name, err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func moduleWorkerRelease(t *testing.T, controls, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(controls, "release-"+name), []byte(name), 0600); err != nil {
		t.Error(err)
	}
}

func moduleWorkerStart(t *testing.T, cfg config, controls string) (context.Context, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		done <- runModule(ctx, cfg)
		close(joined)
	}()
	t.Cleanup(func() {
		cancel()
		for _, name := range []string{"a", "b", "c"} {
			moduleWorkerRelease(t, controls, name)
		}
		<-joined
	})
	return ctx, cancel, done
}

func TestModuleOtherWorkersActualWholePackagesAndStableUnion(t *testing.T) {
	for _, failing := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure-%t", failing), func(t *testing.T) {
			cfg, controls := moduleWorkerFixture(t, failing)
			ctx, _, done := moduleWorkerStart(t, cfg, controls)
			moduleWorkerWaitReady(t, ctx, controls, "a", done)
			moduleWorkerWaitReady(t, ctx, controls, "b", done)
			if _, err := os.Stat(filepath.Join(controls, "active-a")); err != nil {
				t.Fatal("whole packages executed serially instead of sharing two bounded workers", err)
			}
			if _, err := os.Stat(filepath.Join(controls, "ready-c")); !os.IsNotExist(err) {
				t.Fatal("third whole package escaped the two-worker limit", err)
			}
			moduleWorkerRelease(t, controls, "b")
			moduleWorkerWaitReady(t, ctx, controls, "c", done)
			if _, err := os.Stat(filepath.Join(controls, "active-a")); err != nil {
				t.Fatal("first real package did not remain active until independently released", err)
			}
			moduleWorkerRelease(t, controls, "c")
			moduleWorkerRelease(t, controls, "a")
			err := <-done
			if (err != nil) != failing {
				t.Fatal("actual package failure was lost or invented", err)
			}
			var report moduleReport
			if err := ciReadJSON(filepath.Join(cfg.Out, "module.json"), &report); err != nil {
				t.Fatal(err)
			}
			position := 0
			for index, pkg := range report.Inventory {
				if moduleOwner(pkg) != 2 {
					continue
				}
				if position >= len(report.Packages) || report.Packages[position].Package != pkg.Package {
					t.Fatal("collector replaced actual inventory order with worker completion order", report.Packages)
				}
				result := report.Packages[position]
				position++
				wantFailure := failing && strings.HasSuffix(pkg.Package, "/parallel/b")
				wantStatus := "passed"
				if wantFailure {
					wantStatus = "failed"
				}
				if result.Status != wantStatus || result.Shards != 1 || result.Workers != 1 {
					t.Fatal("complete-package resource boundary or original failure changed", result)
				}
				if strings.Contains(pkg.Package, "/parallel/") {
					var suite suiteReport
					out := filepath.Join(cfg.Out, fmt.Sprintf("package-%04d", index))
					if err := ciReadJSON(filepath.Join(out, "report.json"), &suite); err != nil {
						t.Fatal(err)
					}
					if !suite.FullPackage || len(suite.Shards) != 1 || len(suite.Benchmarks) != 1 ||
						len(suite.Names) != 3 || len(suite.Shards[0].Command) == 0 ||
						strings.Contains(strings.Join(suite.Shards[0].Command, " "), "-run=") {
						t.Fatal("whole-package execution lost Test/Example/Fuzz/Benchmark/TestMain semantics", suite)
					}
					for _, root := range []string{"ExampleValue", "FuzzValue", "TestHeld"} {
						if suite.Shards[0].Outcomes[root] == "" {
							t.Fatal("actual whole-package root never executed", root)
						}
					}
					data, err := os.ReadFile(filepath.Join(out, "shard-0000.stdout"))
					if err != nil || strings.Count(string(data), "FULL_PACKAGE_MAIN_") != 1 {
						t.Fatal("TestMain was missing, filtered or repeated", err)
					}
				}
			}
			if position != len(report.Packages) || (report.Status == "failed") != failing {
				t.Fatal("module collector lost packages or original failure", report)
			}
			if failing {
				if err := verifyModuleOwner(report, cfg.Out); err == nil {
					t.Fatal("failed actual package became complete module success")
				}
				return
			}
			container := filepath.Dir(cfg.Out)
			for owner := 0; owner < 2; owner++ {
				other := cfg
				other.ModuleOwner, other.Out = owner, filepath.Join(container, fmt.Sprintf("owner-%04d", owner))
				if err := runModule(ctx, other); err != nil {
					t.Fatal(err)
				}
			}
			aggregate := cfg
			aggregate.ModuleOwner, aggregate.ModuleVerify = -1, container
			aggregate.Out = filepath.Join(t.TempDir(), "aggregate")
			if err := runModule(ctx, aggregate); err != nil {
				t.Fatal("fresh strict aggregate rejected full concurrent-package union", err)
			}
		})
	}
}

func TestModuleOtherWorkersActualCancellationStopsDispatchAndJoins(t *testing.T) {
	cfg, controls := moduleWorkerFixture(t, false)
	ctx, cancel, done := moduleWorkerStart(t, cfg, controls)
	moduleWorkerWaitReady(t, ctx, controls, "a", done)
	moduleWorkerWaitReady(t, ctx, controls, "b", done)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled whole packages became success")
	}
	if _, err := os.Stat(filepath.Join(controls, "ready-c")); !os.IsNotExist(err) {
		t.Fatal("cancellation dispatched an unstarted package", err)
	}
	for _, name := range []string{"a", "b"} {
		data, err := os.ReadFile(filepath.Join(controls, "pid-"+name))
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil || pid <= 0 {
			t.Fatal("invalid actual package process ID", name, string(data), err)
		}
		if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
			if evidence, terminal := moduleWorkerKernelTerminal(pid); terminal {
				t.Logf("actual package exited; its outside-group parent retains a zombie: %s", evidence)
			} else {
				t.Fatal("module returned before actual package process exited", name, pid, err, evidence)
			}
		}
	}
	var report moduleReport
	if err := ciReadJSON(filepath.Join(cfg.Out, "module.json"), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || verifyModuleOwner(report, cfg.Out) == nil {
		t.Fatal("missing or cancelled actual commands became complete success", report)
	}
	for index, pkg := range report.Inventory {
		if strings.HasSuffix(pkg.Package, "/parallel/c") {
			if _, err := os.Lstat(filepath.Join(cfg.Out, fmt.Sprintf("package-%04d", index))); !os.IsNotExist(err) {
				t.Fatal("unstarted package acquired command artifacts", err)
			}
			found := false
			for _, result := range report.Packages {
				if result.Package == pkg.Package {
					found = true
					if result.Status != "pending" {
						t.Fatal("never dispatched package acquired terminal credit", result)
					}
				}
			}
			if !found {
				t.Fatal("cancelled module erased its planned unstarted package")
			}
		}
	}
}
