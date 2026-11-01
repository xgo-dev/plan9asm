//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is an actual multi-package Go module, not a script impersonating Go.
// The nested module must not enter the main module's ./... inventory.
func moduleFixture(t *testing.T, failing bool) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":   "module example.org/modulefixture\n\ngo 1.20\n",
		"value.go": "package fixture\nfunc Value() int { return 7 }\n",
		"value_test.go": `package fixture
import (
    "fmt"
    "testing"
)
func TestAlpha(t *testing.T) { t.Run("child", func(t *testing.T) { if Value() != 7 { t.Fatal("value") } }) }
func TestWorkerOne(t *testing.T) { if Value() != 7 { t.Fatal("value") } }
func ExampleValue() { fmt.Println(Value()); /* Output: 7 */ }
func FuzzValue(f *testing.F) { f.Add(1); f.Fuzz(func(t *testing.T, n int) { if Value() != 7 { t.Fatal(n) } }) }
`,
		"gotoolprofile/value.go": "package profile\nfunc Value() int { return 9 }\n",
		"gotoolprofile/value_test.go": `package profile
import "testing"
func TestAlpha(t *testing.T) { if Value() != 9 { t.Fatal("value") } }
func TestWorkerOne(t *testing.T) { if Value() != 9 { t.Fatal("value") } }
`,
		"internal/other/value.go": "package other\nfunc Value() int { return 11 }\n",
		"internal/other/value_test.go": `package other
import "testing"
func TestCompletePackage(t *testing.T) { if Value() != 11 { t.Fatal("value") } }
`,
		"bench/value.go": "package bench\nfunc Value() int { return 13 }\n",
		"bench/value_test.go": `package bench
import "testing"
func BenchmarkNotExecuted(b *testing.B) { b.Fatal("benchmark ran") }
`,
		"empty/value.go":       "package empty\nfunc Value() int { return 17 }\n",
		"nested/go.mod":        "module example.org/nested\n\ngo 1.20\n",
		"nested/value_test.go": "package nested\nimport \"testing\"\nfunc TestExcluded(t *testing.T) { t.Fatal(\"nested role is separate\") }\n",
	}
	if failing {
		files["value_test.go"] += "\nfunc TestActualFailure(t *testing.T) { t.Fatal(\"sticky original failure\") }\n"
	}
	for name, source := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func moduleFixtureEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOENV", "off")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
}

func runModuleFixtureCLI(t *testing.T, failing bool) (string, string, error) {
	t.Helper()
	moduleFixtureEnvironment(t)
	binary := parallelFixtureCLI(t)
	dir := moduleFixture(t, failing)
	out := filepath.Join(t.TempDir(), "module")
	profile := filepath.Join(filepath.Dir(out), "module.cover")
	stem := filepath.Join(t.TempDir(), "cli")
	_, err := captureCommand(context.Background(), 5*time.Minute, ".", binary,
		[]string{"-module", "-dir", dir, "-out", out, "-shards=2", "-workers=2", "-timeout=2m", "--",
			"-race", "-covermode=atomic", "-coverprofile=" + profile, "-p=2"}, stem)
	return dir, out, errorsWithActualOutput(err, stem)
}

func errorsWithActualOutput(err error, stem string) error {
	if err == nil {
		return nil
	}
	stderr, _ := os.ReadFile(stem + ".stderr")
	return fmt.Errorf("%w\n%s", err, stderr)
}

func TestModuleCLIActualInventoryAndAllPackageCoverage(t *testing.T) {
	_, out, err := runModuleFixtureCLI(t, false)
	if err != nil {
		t.Fatalf("actual exhaustive module CLI: %v", err)
	}
	var report struct {
		Status   string `json:"status"`
		Packages []struct {
			Package string `json:"package"`
			Status  string `json:"status"`
			Shards  int    `json:"shards"`
			Workers int    `json:"workers"`
		} `json:"packages"`
	}
	data, err := os.ReadFile(filepath.Join(out, "module.json"))
	if err != nil || json.Unmarshal(data, &report) != nil || report.Status != "passed" || len(report.Packages) != 5 {
		t.Fatalf("complete actual module denominator: %s (%v)", data, err)
	}
	for _, pkg := range report.Packages {
		partitioned := pkg.Package == "example.org/modulefixture" || strings.HasSuffix(pkg.Package, "/gotoolprofile")
		if pkg.Status != "passed" || partitioned && (pkg.Shards != 2 || pkg.Workers != 2) ||
			!partitioned && (pkg.Shards != 1 || pkg.Workers != 1) {
			t.Fatalf("package role or complete execution changed: %+v", pkg)
		}
	}
	coverage, err := os.ReadFile(filepath.Join(filepath.Dir(out), "module.cover"))
	if err != nil || !strings.HasPrefix(string(coverage), "mode: atomic\n") {
		t.Fatalf("actual module-wide coverage absent: %v\n%s", err, coverage)
	}
	for _, name := range []string{"modulefixture/value.go:", "modulefixture/gotoolprofile/value.go:", "modulefixture/internal/other/value.go:", "modulefixture/bench/value.go:"} {
		if !strings.Contains(string(coverage), name) {
			t.Errorf("coverage silently became root-only or lost a test-bearing package: %s\n%s", name, coverage)
		}
	}
}

func TestModuleCLIFailureRetainsLaterCompletePackages(t *testing.T) {
	_, out, err := runModuleFixtureCLI(t, true)
	if err == nil || !strings.Contains(err.Error(), "package example.org/modulefixture:") {
		t.Fatalf("actual source failure cause missing: %v", err)
	}
	files, globErr := filepath.Glob(filepath.Join(out, "package-0000", "shard-*.stdout"))
	failureObserved := false
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		failureObserved = failureObserved || strings.Contains(string(data), "sticky original failure")
	}
	if globErr != nil || !failureObserved {
		t.Fatalf("actual original source diagnostic lost: %v", globErr)
	}
	data, readErr := os.ReadFile(filepath.Join(out, "module.json"))
	var report struct {
		Status   string `json:"status"`
		Packages []struct {
			Package string `json:"package"`
			Status  string `json:"status"`
		} `json:"packages"`
	}
	if readErr != nil || json.Unmarshal(data, &report) != nil || report.Status != "failed" || len(report.Packages) != 5 {
		t.Fatalf("failure lost the complete package plan: %s (%v)", data, readErr)
	}
	for _, pkg := range report.Packages {
		if pkg.Package != "example.org/modulefixture" && pkg.Status != "passed" {
			t.Errorf("sticky failure prevented another complete package: %+v", pkg)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(out), "module.cover")); !os.IsNotExist(err) {
		t.Fatalf("failed module published uploadable merged coverage: %v", err)
	}
}
