package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func windowsModuleExecutionFixture(t *testing.T) config {
	t.Helper()
	cfg, _ := windowsModuleDependencyFixture(t)
	files := map[string]string{
		"value.go": "package consumer\nfunc Value() int { return 7 }\n",
		"value_test.go": `package consumer
import ("fmt"; "testing")
func TestAlpha(t *testing.T) {
    t.Run("child", func(t *testing.T) {
        c := Context()
        defer c.Dispose()
        if Value() != 7 { t.Fatal("value") }
    })
}
func TestBeta(t *testing.T) { if Value() != 7 { t.Fatal("value") } }
func ExampleValue() { fmt.Println(Value()); /* Output: 7 */ }
func FuzzValue(f *testing.F) {
    f.Add(1)
    f.Fuzz(func(t *testing.T, n int) { if Value() != 7 { t.Fatal(n) } })
}
`,
		"gotoolprofile/value.go": "package profile\nfunc Value() int { return 9 }\n",
		"gotoolprofile/value_test.go": `package profile
import "testing"
func TestProfile(t *testing.T) { if Value() != 9 { t.Fatal("value") } }
`,
		"internal/other/value.go": "package other\nfunc Value() int { return 11 }\n",
		"internal/other/value_test.go": `package other
import "testing"
func TestCompletePackage(t *testing.T) { if Value() != 11 { t.Fatal("value") } }
`,
		"empty/value.go": "package empty\nfunc Value() int { return 13 }\n",
		"nested/go.mod":  "module example.org/separate\n\ngo 1.20\n",
		"nested/value_test.go": `package separate
import "testing"
func TestNeverInParentInventory(t *testing.T) { t.Fatal("separate module") }
`,
	}
	for name, source := range files {
		path := filepath.Join(cfg.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Package, cfg.CIOwner, cfg.ModuleOwner = ".", -1, -1
	cfg.Shards, cfg.Workers = 2, 1
	cfg.ModuleRootPartitions, cfg.ModuleRootPartition = 2, -1
	return cfg
}

func windowsModuleExecutionReport(t *testing.T, cfg config) (moduleReport, error) {
	t.Helper()
	err := runModule(context.Background(), cfg)
	var report moduleReport
	if readErr := ciReadJSON(filepath.Join(cfg.Out, "module.json"), &report); readErr != nil {
		t.Fatalf("module report missing after %v: %v", err, readErr)
	}
	if err != nil {
		_ = filepath.WalkDir(cfg.Out, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr == nil && !entry.IsDir() && strings.HasSuffix(path, ".stderr") {
				data, readErr := os.ReadFile(path)
				if readErr == nil && len(data) != 0 {
					t.Logf("%s: %q", filepath.Base(path), data)
				}
			}
			return walkErr
		})
	}
	return report, err
}

func TestWindowsModuleActualPartitionsAndCoverage(t *testing.T) {
	cfg := windowsModuleExecutionFixture(t)
	inputs := t.TempDir()
	if err := os.Mkdir(filepath.Join(inputs, "owner-0000"), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(t.TempDir(), "complete.cover")
	cfg.Flags = append(cfg.Flags, "-p=2", "-covermode=atomic", "-coverprofile="+profile)
	for owner := 0; owner < moduleOwners; owner++ {
		parts := 1
		if owner == 0 {
			parts = cfg.ModuleRootPartitions
		}
		for part := 0; part < parts; part++ {
			child := cfg
			wantStatus := "passed"
			child.ModuleOwner = owner
			child.Out = filepath.Join(inputs, fmt.Sprintf("owner-%04d", owner))
			if owner == 0 {
				wantStatus = "completed_owned"
				child.ModuleRootPartition = part
				child.Out = filepath.Join(child.Out, fmt.Sprintf("part-%04d", part))
			}
			report, err := windowsModuleExecutionReport(t, child)
			if err != nil || report.Status != wantStatus || len(report.Inventory) != 4 {
				t.Fatalf("Windows module owner %d part %d: status=%s, inventory=%d; %v", owner, part, report.Status, len(report.Inventory), err)
			}
		}
	}
	if _, err := os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatalf("owner published incomplete uploadable coverage: %v", err)
	}
	cfg.ModuleVerify, cfg.Out = inputs, filepath.Join(t.TempDir(), "aggregate")
	report, err := windowsModuleExecutionReport(t, cfg)
	if err != nil || report.Status != "passed" || len(report.Packages) != 4 ||
		report.RootInventory == nil || len(report.RootInventory.Names) != 4 {
		t.Fatalf("Windows complete actual package/root union: status=%s, packages=%d, roots=%+v; %v", report.Status, len(report.Packages), report.RootInventory, err)
	}
	coverage, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"consumer.go:", "value.go:", "gotoolprofile/value.go:", "internal/other/value.go:"} {
		if !strings.Contains(string(coverage), name) {
			t.Fatalf("Windows complete module coverage lost %s", name)
		}
	}
	part := filepath.Join(inputs, "owner-0000", "part-0000")
	retained := filepath.Join(t.TempDir(), "retained")
	if err := os.Rename(part, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := checkedModuleArtifacts(report, inputs); err == nil {
		t.Fatal("missing Windows root partition became complete")
	}
	if err := os.Rename(retained, part); err != nil {
		t.Fatal(err)
	}
	if _, err := checkedModuleArtifacts(report, inputs); err != nil {
		t.Fatalf("restored actual Windows partition union: %v", err)
	}
}

func TestWindowsModuleActualFailureKeepsRemainingPackages(t *testing.T) {
	cfg := windowsModuleExecutionFixture(t)
	path := filepath.Join(cfg.Dir, "failure_test.go")
	if err := os.WriteFile(path, []byte("package consumer\nimport \"testing\"\nfunc TestActualFailure(t *testing.T) { t.Fatal(\"original failure\") }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.ModuleRootPartitions = 1
	cfg.Out = filepath.Join(t.TempDir(), "failed")
	profile := filepath.Join(t.TempDir(), "failed.cover")
	cfg.Flags = append(cfg.Flags, "-p=2", "-coverprofile="+profile)
	report, err := windowsModuleExecutionReport(t, cfg)
	if err == nil || report.Status != "failed" || len(report.Packages) != 4 ||
		report.Packages[0].Status != "failed" {
		t.Fatalf("actual Windows source failure lost: status=%s, packages=%+v; %v", report.Status, report.Packages, err)
	}
	for _, pkg := range report.Packages[1:] {
		if pkg.Status != "passed" {
			t.Fatalf("root failure suppressed remaining package: %+v", pkg)
		}
	}
	if _, err := os.Lstat(profile); !os.IsNotExist(err) {
		t.Fatalf("failed module published uploadable coverage: %v", err)
	}
}
