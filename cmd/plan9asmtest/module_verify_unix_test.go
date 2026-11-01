//go:build unix

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestModuleThreeOwnersActualGoAndStrictAggregate(t *testing.T) {
	moduleFixtureEnvironment(t)
	binary := parallelFixtureCLI(t)
	dir := moduleFixture(t, false)
	frontend := filepath.Join(dir, "internal", "sdkfrontend")
	if err := os.MkdirAll(frontend, 0700); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"value.go": "package frontend\nfunc Value() int { return 19 }\n",
		"value_test.go": `package frontend
import ("fmt"; "testing")
func TestCaptureAlpha(t *testing.T) { t.Run("child", func(t *testing.T) { if Value()!=19 { t.Fatal("value") } }) }
func TestCaptureBeta(t *testing.T) { if Value()!=19 { t.Fatal("value") } }
func ExampleValue() { fmt.Println(Value()); /* Output: 19 */ }
func FuzzValue(f *testing.F) { f.Add(19); f.Fuzz(func(t *testing.T, n int) { if Value()!=n { t.Fatal(n) } }) }
`,
	} {
		if err := os.WriteFile(filepath.Join(frontend, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	container := t.TempDir()
	profile := filepath.Join(t.TempDir(), "whole-module.cover")
	flags := []string{"-race", "-covermode=atomic", "-coverprofile=" + profile, "-p=2"}
	var expected moduleReport
	frontendIndex := -1
	for owner := 0; owner < moduleOwners; owner++ {
		out := filepath.Join(container, fmt.Sprintf("owner-%04d", owner))
		stem := filepath.Join(t.TempDir(), "owner")
		args := []string{"-module", fmt.Sprintf("-module-owner=%d", owner), "-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--"}
		args = append(args, flags...)
		if _, err := captureCommand(context.Background(), 4*time.Minute, ".", binary, args, stem); err != nil {
			t.Fatal(errorsWithActualOutput(err, stem))
		}
		var report moduleReport
		if err := ciReadJSON(filepath.Join(out, "module.json"), &report); err != nil {
			t.Fatal(err)
		}
		if owner == 0 {
			expected = report
			expected.Owner = -1
		}
		if len(report.Inventory) != 6 || report.Status != "passed" {
			t.Fatalf("owner lost actual whole-module inventory: %+v", report)
		}
		for index, pkg := range report.Inventory {
			if pkg.Directory != "internal/sdkfrontend" {
				continue
			}
			frontendIndex = index
			if moduleOwner(pkg) != 1 {
				t.Fatal("actual SDK frontend remained a serial whole-package owner")
			}
			if owner != 1 {
				continue
			}
			var suite suiteReport
			packageOut := filepath.Join(out, fmt.Sprintf("package-%04d", index))
			if err := ciReadJSON(filepath.Join(packageOut, "report.json"), &suite); err != nil {
				t.Fatal(err)
			}
			if suite.FullPackage || suite.Workers != 2 || len(suite.Shards) != 2 ||
				len(suite.Names) != 4 || suite.RootPassed != 4 || suite.ChildPassed != 2 ||
				suite.RootSkipped != 0 || suite.ChildSkipped != 0 {
				t.Fatalf("SDK frontend lost complete Test/Example/Fuzz roots and children: %+v", suite)
			}
		}
	}
	if _, err := os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatalf("an owner published partial module coverage: %v", err)
	}
	// Downloaded artifacts need not retain their original physical directory.
	// Only known artifact-root roles move; source/SDK/env/tool fields stay exact.
	relocated := filepath.Join(t.TempDir(), "downloaded")
	if err := os.Rename(container, relocated); err != nil {
		t.Fatal(err)
	}
	if err := verifyModuleArtifacts(expected, relocated); err != nil {
		t.Fatalf("complete actual disjoint owner artifacts: %v", err)
	}
	stem := filepath.Join(t.TempDir(), "aggregate")
	args := []string{"-module", "-dir", dir, "-out", filepath.Join(t.TempDir(), "verified"), "-verify-module", relocated, "-shards=2", "-workers=2", "-timeout=2m", "--"}
	args = append(args, flags...)
	if _, err := captureCommand(context.Background(), 3*time.Minute, ".", binary, args, stem); err != nil {
		t.Fatal(errorsWithActualOutput(err, stem))
	}
	data, err := os.ReadFile(profile)
	if err != nil || !strings.Contains(string(data), "modulefixture/internal/other/value.go:") ||
		!strings.Contains(string(data), "modulefixture/gotoolprofile/value.go:") ||
		!strings.Contains(string(data), "modulefixture/internal/sdkfrontend/value.go:") {
		t.Fatalf("checked cross-owner coverage lost packages: %v\n%s", err, data)
	}

	ownerPath := filepath.Join(relocated, "owner-0002", "module.json")
	var original moduleReport
	if err := ciReadJSON(ownerPath, &original); err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		change func(*moduleReport)
	}{
		{"missing-package", func(r *moduleReport) { r.Packages = r.Packages[:len(r.Packages)-1] }},
		{"duplicate-package", func(r *moduleReport) { r.Packages[1] = r.Packages[0] }},
		{"foreign-package", func(r *moduleReport) { r.Packages[0].Package = "example.org/foreign" }},
		{"partial", func(r *moduleReport) { r.Packages[0].Status = "pending" }},
		{"flag", func(r *moduleReport) { r.Flags = append(r.Flags, "-race=false") }},
		{"source", func(r *moduleReport) { r.Scope.SourceSHA = strings.Repeat("0", 64) }},
		{"sdk", func(r *moduleReport) { r.Scope.SDKSource = strings.Repeat("0", 64) }},
		{"tool", func(r *moduleReport) { r.Scope.Tools["go"] = strings.Repeat("0", 64) }},
		{"environment", func(r *moduleReport) { r.Scope.Environment["GOGCCFLAGS"] += " -Dforeign" }},
		{"budget", func(r *moduleReport) { r.Timeout = "3m0s" }},
		{"unknown-protocol", func(r *moduleReport) { r.Protocol = "unregistered" }},
		{"lost-skip", func(r *moduleReport) { r.Packages[0].RootSkipped++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			// A fresh decode gives every mutation independent slices/maps.
			var changed moduleReport
			if err := ciReadJSON(ownerPath, &changed); err != nil {
				t.Fatal(err)
			}
			mutation.change(&changed)
			if err := ciWriteJSON(ownerPath, changed); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ciWriteJSON(ownerPath, original); err != nil {
					t.Error(err)
				}
			})
			if err := verifyModuleArtifacts(expected, relocated); err == nil {
				t.Fatal("foreign/incomplete artifact became complete")
			}
		})
	}
	packagePath := filepath.Join(relocated, "owner-0000", "package-0000", "report.json")
	var suite suiteReport
	if err := ciReadJSON(packagePath, &suite); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing-root", "unknown-root", "duplicate-shard", "missing-benchmark", "command", "coverage", "raw-incomplete", "raw-foreign"} {
		t.Run(name, func(t *testing.T) {
			var changed suiteReport
			if err := ciReadJSON(packagePath, &changed); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing-root":
				changed.Names = changed.Names[1:]
			case "unknown-root":
				changed.Names = append(changed.Names, "TestForeign")
			case "duplicate-shard":
				changed.Shards[1] = changed.Shards[0]
			case "missing-benchmark":
				changed.Benchmarks = []string{"BenchmarkForeign"}
			case "command":
				changed.Shards[0].Command = append(changed.Shards[0].Command, "-run=TestForeign")
			case "coverage":
				path := filepath.Join(filepath.Dir(packagePath), "package.cover")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("mode: atomic\n"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Error(err)
					}
				})
			case "raw-incomplete", "raw-foreign":
				path := filepath.Join(filepath.Dir(packagePath), "shard-0000.stdout")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				changed := []byte{}
				if name == "raw-foreign" {
					changed = bytes.ReplaceAll(data, []byte("example.org/modulefixture"), []byte("example.org/foreign"))
				}
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Error(err)
					}
				})
			}
			if err := ciWriteJSON(packagePath, changed); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := ciWriteJSON(packagePath, suite); err != nil {
					t.Error(err)
				}
			})
			if err := verifyModuleArtifacts(expected, relocated); err == nil {
				t.Fatal("missing/foreign raw execution or coverage became complete")
			}
		})
	}
	frontendOut := filepath.Join(relocated, "owner-0001", fmt.Sprintf("package-%04d", frontendIndex))
	logs, err := filepath.Glob(filepath.Join(frontendOut, "shard-*.stdout"))
	if err != nil || len(logs) == 0 {
		t.Fatal("SDK frontend has no actual executing Go JSON", err)
	}
	for _, name := range []string{"sdk-raw-incomplete", "sdk-raw-duplicate"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(logs[0])
			if err != nil {
				t.Fatal(err)
			}
			var changed []byte
			if name == "sdk-raw-duplicate" {
				changed = append(append([]byte(nil), data...), data...)
			}
			if err := os.WriteFile(logs[0], changed, 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.WriteFile(logs[0], data, 0600); err != nil {
					t.Error(err)
				}
			})
			if err := verifyModuleArtifacts(expected, relocated); err == nil {
				t.Fatal("missing or repeated SDK frontend execution became complete")
			}
		})
	}
	if err := verifyModuleArtifacts(expected, relocated); err != nil {
		t.Fatalf("negative controls mutated original artifact state: %v", err)
	}
	if reflect.DeepEqual(expected.Scope.Tools, original.Scope.Tools) == false {
		t.Fatal("mutation leaked into immutable expected plan")
	}
}

func TestModuleExplicitSkipIsNeverAPassedRoot(t *testing.T) {
	moduleFixtureEnvironment(t)
	dir := moduleFixture(t, false)
	path := filepath.Join(dir, "value_test.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = append(source, []byte("\nfunc TestExistingSkip(t *testing.T) { t.Skip(\"original explicit platform role\") }\n")...)
	if err := os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	binary := parallelFixtureCLI(t)
	out := filepath.Join(t.TempDir(), "module")
	stem := filepath.Join(t.TempDir(), "cli")
	if _, err := captureCommand(context.Background(), 4*time.Minute, ".", binary,
		[]string{"-module", "-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--", "-p=2"}, stem); err != nil {
		t.Fatal(errorsWithActualOutput(err, stem))
	}
	var report moduleReport
	if err := ciReadJSON(filepath.Join(out, "module.json"), &report); err != nil {
		t.Fatal(err)
	}
	var suite suiteReport
	if err := ciReadJSON(filepath.Join(out, "package-0000", "report.json"), &suite); err != nil {
		t.Fatal(err)
	}
	if report.Status != "completed_with_skips" || report.Packages[0].RootSkipped != 1 || suite.RootSkipped != 1 || suite.RootPassed != 4 {
		t.Fatalf("explicit original skip was lost or relabeled P: %+v / %+v", report, suite)
	}
	results, err := checkedModuleArtifacts(report, out)
	if err != nil || len(results) != 5 || results[0].RootSkipped != 1 {
		t.Fatalf("aggregate lost explicit original skip: %+v %v", results, err)
	}
}

func TestModuleBenchmarkOnlyRootExecutesActualTestMain(t *testing.T) {
	moduleFixtureEnvironment(t)
	dir := moduleFixture(t, false)
	// Empty root inventories still have real TestMain code, which must run.
	source := `package fixture
import ("os"; "testing")
func TestMain(m *testing.M) { if Value() != 7 { os.Exit(3) }; os.Exit(m.Run()) }
func BenchmarkNotRun(b *testing.B) { b.Fatal("benchmark executed") }
`
	if err := os.WriteFile(filepath.Join(dir, "value_test.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	binary := parallelFixtureCLI(t)
	out := filepath.Join(t.TempDir(), "module")
	stem := filepath.Join(t.TempDir(), "cli")
	if _, err := captureCommand(context.Background(), 4*time.Minute, ".", binary,
		[]string{"-module", "-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--", "-p=2"}, stem); err != nil {
		t.Fatal(errorsWithActualOutput(err, stem))
	}
	var report suiteReport
	if err := ciReadJSON(filepath.Join(out, "package-0000", "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Names) != 0 || len(report.Benchmarks) != 1 || !report.FullPackage || len(report.Shards) != 1 || strings.Contains(strings.Join(report.Shards[0].Command, " "), "-run=") {
		t.Fatalf("benchmark-only root did not execute complete unfiltered package: %+v", report)
	}
}
