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

func TestWindowsActualInventoryPartitionsAndCoverage(t *testing.T) {
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	for _, fail := range []bool{false, true} {
		name := "complete"
		if fail {
			name = "retain-failure"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			source := `package fixture
import (
    "fmt"
    "testing"
)
func TestAlpha(t *testing.T) {
    t.Parallel()
    t.Run("child", func(t *testing.T) { if Value() != 7 { t.Fatal("value") } })
}
func TestBeta(t *testing.T) { if Value() != 7 { t.Fatal("value") } }
func Example() { fmt.Println(Value()); /* Output: 7 */ }
func FuzzSeeds(f *testing.F) {
    f.Add(1)
    f.Add(2)
    f.Fuzz(func(t *testing.T, input int) { if Value() != 7 { t.Fatal(input) } })
}
func BenchmarkNotRun(b *testing.B) { b.Fatal("ordinary suite ran a benchmark") }
`
			if fail {
				source += "\nfunc TestFails(t *testing.T) { t.Fatal(\"actual fixture failure\") }\n"
			}
			for file, data := range map[string]string{
				"go.mod":        "module example.org/windows-runner-fixture\n\ngo 1.20\n",
				"value.go":      "package fixture\nfunc Value() int { return 7 }\n",
				"value_test.go": source,
			} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(t.TempDir(), "artifacts")
			cfg := config{Go: "go", Dir: dir, Package: ".", Out: out, Shards: 4, Workers: 2,
				Timeout: 2 * time.Minute, Flags: []string{"-covermode=atomic", "-coverprofile=complete.cover"}}
			err := runSuite(context.Background(), cfg)
			if (err != nil) != fail {
				t.Fatalf("actual suite failure=%t: %v", fail, err)
			}
			data, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report suiteReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.RootPassed != 4 || report.RootSkipped != 0 || report.RootMissing != 0 ||
				report.ChildPassed != 3 || report.ChildSkipped != 0 || report.ChildMissing != 0 ||
				report.ChildFailed != 0 || len(report.Benchmarks) != 1 || report.Workers != 2 {
				t.Fatalf("actual complete roots/seeds/children differ: %+v", report)
			}
			profile, profileErr := os.ReadFile(filepath.Join(dir, "complete.cover"))
			if fail {
				if report.Status != "failed" || report.RootFailed != 1 || len(report.Names) != 5 || !os.IsNotExist(profileErr) {
					t.Fatalf("failed suite lost its root or published complete coverage: %+v, %v", report, profileErr)
				}
			} else if report.Status != "passed" || report.RootFailed != 0 || len(report.Names) != 4 ||
				profileErr != nil || !strings.HasPrefix(string(profile), "mode: atomic\n") {
				t.Fatalf("complete suite/profile missing: %+v, %v", report, profileErr)
			}
		})
	}
}
