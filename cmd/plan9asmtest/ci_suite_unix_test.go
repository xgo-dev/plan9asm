//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ciFixtureConfig(t *testing.T, source string) config {
	t.Helper()
	for key, value := range map[string]string{"GOFLAGS": "", "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "PLAN9ASM_CROSS_EXEC": ""} {
		t.Setenv(key, value)
	}
	return config{Go: "go", Dir: fixture(t, source), Package: ".", Shards: 3, Timeout: 4 * time.Minute, CISelector: "^Test", CIIsolate: "TestGiant", CIOwner: -1, Flags: []string{"-p=2"}}
}

func readCIReport(t *testing.T, directory string) ciReport {
	t.Helper()
	var report ciReport
	if err := ciReadJSON(filepath.Join(directory, "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestActualGoCIAllOwnersAndStrictAggregate(t *testing.T) {
	cfg := ciFixtureConfig(t, `package fixture
import "testing"
func TestGiant(t *testing.T) { t.Run("seed", func(t *testing.T) {}) }
func TestAlpha(t *testing.T) {}
func TestBeta(t *testing.T) {}
func Example() { /* Output: */ }
`)
	artifacts := t.TempDir()
	var expected ciPlan
	originalCache := os.Getenv("GOCACHE")
	for owner := 0; owner < cfg.Shards; owner++ {
		if owner == 1 {
			// A separate real cache also forces the SDK's lazy-tool route. Its
			// bytes must agree, not its worker-specific cached filename.
			t.Setenv("GOCACHE", t.TempDir())
		} else {
			t.Setenv("GOCACHE", originalCache)
		}
		cfg.CIOwner = owner
		cfg.Out = filepath.Join(artifacts, ownerDirectory(owner))
		if err := runCI(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		report := readCIReport(t, cfg.Out)
		if owner == 0 {
			expected = report.Plan
			if len(report.Roots) != 1 || report.Roots[0].Name != "TestGiant" {
				t.Fatal("giant was not isolated", report.Roots)
			}
		}
	}
	if len(expected.Inventory) != 4 || len(expected.Selected) != 3 {
		t.Fatal("ordinary nonselected scope erased", expected)
	}
	if err := verifyCIArtifacts(expected, artifacts); err != nil {
		t.Fatal(err)
	}
	cfg.CIOwner, cfg.CIVerify = -1, artifacts
	cfg.Out = filepath.Join(t.TempDir(), "aggregate")
	if err := runCI(context.Background(), cfg); err != nil {
		t.Fatal("fresh actual-list aggregate", err)
	}
	// Each mutation starts from a fresh decoded actual report, not an in-memory
	// shared map whose earlier mutation can accidentally make later axes pass.
	ownerPath := filepath.Join(artifacts, ownerDirectory(0), "report.json")
	baseline, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ciReport){
		"missing root":        func(r *ciReport) { r.Roots = nil },
		"duplicate root":      func(r *ciReport) { r.Roots = append(r.Roots, r.Roots[0]) },
		"unknown root":        func(r *ciReport) { r.Roots[0].Name = "TestUnknown" },
		"partial":             func(r *ciReport) { r.Final = nil },
		"foreign source":      func(r *ciReport) { r.Plan.Scope.SourceSHA = "foreign"; r.Final.SourceSHA = "foreign" },
		"foreign SDK":         func(r *ciReport) { r.Plan.Scope.Tools["go"] = "foreign"; r.Final.Tools["go"] = "foreign" },
		"foreign SDK source":  func(r *ciReport) { r.Plan.Scope.SDKSource = "foreign"; r.Final.SDKSource = "foreign" },
		"foreign flags":       func(r *ciReport) { r.Plan.Flags = []string{"-race"} },
		"foreign environment": func(r *ciReport) { r.Plan.Scope.Environment["CGO_ENABLED"] = "foreign" },
		"reassigned":          func(r *ciReport) { r.Owner = 1 },
		"short timeout":       func(r *ciReport) { r.Plan.Timeout = "1s" },
		"paired plan erasure": func(r *ciReport) { r.Plan.Selected = nil; r.Roots = nil },
		"exit forged":         func(r *ciReport) { r.Roots[0].Exit = 1 },
		"failed relabel":      func(r *ciReport) { r.Roots[0].Error = "actual failure" },
		"filtered command":    func(r *ciReport) { r.Roots[0].Command = append(r.Roots[0].Command, "-skip=.") },
		"raw identity":        func(r *ciReport) { r.Roots[0].Output = "foreign" },
		"paired tool path": func(r *ciReport) {
			r.Go = "/foreign/bin/go"
			r.Roots[0].Command[0] = r.Go
		},
		"escaping artifact": func(r *ciReport) { r.Roots[0].Stem = "../root-0000" },
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			var report ciReport
			if err := json.Unmarshal(baseline, &report); err != nil {
				t.Fatal(err)
			}
			mutation(&report)
			if err := ciWriteJSON(ownerPath, report); err != nil {
				t.Fatal(err)
			}
			if err := verifyCIArtifacts(expected, artifacts); err == nil {
				t.Fatal("mutation admitted")
			}
		})
	}
	if err := os.WriteFile(ownerPath, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCIArtifacts(expected, artifacts); err != nil {
		t.Fatal("mutation control", err)
	}
	envPath := filepath.Join(artifacts, ownerDirectory(0), "before-env.stdout")
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GOGCCFLAGS", "GOCACHEPROG", "FUTURE_SEMANTIC_INPUT"} {
		t.Run("complete actual environment/"+key, func(t *testing.T) {
			var environment map[string]string
			if err := json.Unmarshal(envBytes, &environment); err != nil {
				t.Fatal(err)
			}
			environment[key] += " changed"
			if err := ciWriteJSON(envPath, environment); err != nil {
				t.Fatal(err)
			}
			if err := verifyCIArtifacts(expected, artifacts); err == nil {
				t.Fatal("uncaptured actual environment field admitted")
			}
		})
	}
	if err := os.WriteFile(envPath, envBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCIArtifacts(expected, artifacts); err != nil {
		t.Fatal("complete environment mutation control", err)
	}
	missing := filepath.Join(artifacts, ownerDirectory(2))
	if err := os.Rename(missing, missing+"-unknown"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCIArtifacts(expected, artifacts); err == nil {
		t.Fatal("unknown/missing owner accepted")
	}
}

func ownerDirectory(owner int) string { return fmt.Sprintf("cross-runtime-owner-%d", owner) }

func TestActualGoCILateSourceMutationRevokesCompletion(t *testing.T) {
	cfg := ciFixtureConfig(t, `package fixture
import (
    "os"
    "testing"
)
func TestGiant(t *testing.T) {
    if err := os.WriteFile("value.go", []byte("package fixture\nfunc value() int { return 9 }\n"), 0600); err != nil { t.Fatal(err) }
}
`)
	cfg.CIOwner = 0
	cfg.Out = filepath.Join(t.TempDir(), "late-change")
	if err := runCI(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal("actual late source change accepted", err)
	}
	report := readCIReport(t, cfg.Out)
	if len(report.Roots) != 1 || report.Roots[0].Status != "passed" || report.Status != "failed" || report.Final != nil {
		t.Fatal("successful raw test substituted for stable provenance", report)
	}
}

func TestActualGoCICancellationRetainsIncompleteRoot(t *testing.T) {
	// Readiness belongs outside the observed source tree: executing the root
	// must not itself revoke the otherwise unchanged source observation.
	ready := filepath.Join(t.TempDir(), "root-ready")
	cfg := ciFixtureConfig(t, fmt.Sprintf(`package fixture
import (
    "os"
    "testing"
)
func TestGiant(t *testing.T) {
    ready := %q
    if err := os.WriteFile(ready+".pending", []byte("TestGiant started\n"), 0600); err != nil { t.Fatal(err) }
    if err := os.Rename(ready+".pending", ready); err != nil { t.Fatal(err) }
    select {}
}
`, ready))
	cfg.CIOwner = 0
	cfg.Out = filepath.Join(t.TempDir(), "cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runCI(ctx, cfg) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	// Planning and a cold SDK build are not the cancellation under test. Keep
	// their existing command bound, then begin the original four-second window
	// only once this exact root has actually entered its body.
	preparation := time.NewTimer(cfg.Timeout)
	defer preparation.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		data, err := os.ReadFile(ready)
		if err == nil {
			if string(data) != "TestGiant started\n" {
				t.Fatal("unexpected root readiness marker", string(data))
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("CI owner ended before its actual root started", err)
		case <-preparation.C:
			t.Fatal("actual root did not start within its original command budget")
		case <-poll.C:
		}
	}
	running := time.NewTimer(4 * time.Second)
	defer running.Stop()
	select {
	case err := <-done:
		joined = true
		t.Fatal("actual root ended before cancellation", err)
	case <-running.C:
		cancel()
	}
	err := <-done
	joined = true
	if err == nil {
		t.Fatal("cancelled child accepted")
	}
	report := readCIReport(t, cfg.Out)
	if report.Status != "failed" || len(report.Roots) != 1 || report.Roots[0].Status != "failed" || report.Roots[0].Exit == 0 || report.Final != nil {
		t.Fatal("cancellation lost incomplete receipt", report)
	}
}

func TestActualGoCIFreshPerRootBudget(t *testing.T) {
	cfg := ciFixtureConfig(t, `package fixture
import (
    "testing"
    "time"
)
func TestGiant(t *testing.T) { time.Sleep(1100*time.Millisecond) }
func TestAlpha(t *testing.T) { time.Sleep(1100*time.Millisecond) }
func TestBeta(t *testing.T) { time.Sleep(1100*time.Millisecond) }
func TestDelta(t *testing.T) { time.Sleep(1100*time.Millisecond) }
func TestGamma(t *testing.T) { time.Sleep(1100*time.Millisecond) }
`)
	// Warm only compilation/listing, not results, so the comparison is the
	// exact same safe original roots with the same four-second child deadline.
	warm := filepath.Join(t.TempDir(), "warm")
	if _, err := captureCommand(context.Background(), cfg.Timeout, cfg.Dir, cfg.Go, []string{"test", "-count=1", "-list=.", "."}, warm); err != nil {
		t.Fatal(err)
	}
	monolithic := filepath.Join(t.TempDir(), "monolithic")
	if _, err := captureCommand(context.Background(), 4*time.Second, cfg.Dir, cfg.Go, []string{"test", "-count=1", "-timeout=4s", "-json", "-run=^Test", "."}, monolithic); err == nil {
		t.Fatal("original combined command unexpectedly fit all five roots")
	} else {
		t.Logf("original combined command actual deadline rejection: %v", err)
		output, readErr := os.ReadFile(monolithic + ".stdout")
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Logf("original combined raw Go JSON (not complete):\n%s", output)
	}
	cfg.Shards, cfg.CIOwner, cfg.Timeout = 2, 1, 4*time.Second
	cfg.Out = filepath.Join(t.TempDir(), "fresh-budgets")
	if err := runCI(context.Background(), cfg); err != nil {
		t.Fatal("same per-child budget was not fresh", err)
	}
	report := readCIReport(t, cfg.Out)
	if report.Plan.Timeout != "4s" || len(report.Roots) != 4 || report.Status != "passed" {
		t.Fatal("roots/budgets lost", report)
	}
}

func TestActualGoCIFailureStickyAndSkipNotPass(t *testing.T) {
	for name, body := range map[string]string{"failure": `t.Fatal("actual failure")`, "skip": `t.Skip("explicit platform boundary")`} {
		t.Run(name, func(t *testing.T) {
			cfg := ciFixtureConfig(t, "package fixture\nimport \"testing\"\nfunc TestGiant(t *testing.T) {}\nfunc TestAlpha(t *testing.T) { "+body+" }\nfunc TestRemaining(t *testing.T) {}\n")
			cfg.Shards, cfg.CIOwner = 2, 1
			cfg.Out = filepath.Join(t.TempDir(), "owner")
			if err := runCI(context.Background(), cfg); err == nil {
				t.Fatal("failure/Skip promoted")
			}
			report := readCIReport(t, cfg.Out)
			if report.Status != "failed" || len(report.Roots) != 2 || report.Roots[1].Name != "TestRemaining" || report.Roots[1].Status != "passed" || report.Final == nil {
				t.Fatal("failure lost or later root not executed", report)
			}
		})
	}
}

func TestCIRawTerminalsRemainIndependent(t *testing.T) {
	plan := ciPlan{Package: "fixture"}
	for name, raw := range map[string]string{
		"missing":          "",
		"unknown":          `{"Action":"start","Package":"fixture"}` + "\n" + `{"Action":"run","Package":"fixture","Test":"TestOther"}` + "\n",
		"incomplete child": `{"Action":"start","Package":"fixture"}` + "\n" + `{"Action":"run","Package":"fixture","Test":"TestAlpha"}` + "\n" + `{"Action":"run","Package":"fixture","Test":"TestAlpha/seed"}` + "\n" + `{"Action":"pass","Package":"fixture","Test":"TestAlpha"}` + "\n" + `{"Action":"pass","Package":"fixture"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "root-0000.stdout"), []byte(raw), 0600)
			os.WriteFile(filepath.Join(dir, "root-0000.stderr"), nil, 0600)
			out, _ := ciFileSHA(filepath.Join(dir, "root-0000.stdout"))
			stderr, _ := ciFileSHA(filepath.Join(dir, "root-0000.stderr"))
			root := ciRootReceipt{Name: "TestAlpha", Stem: "root-0000", Output: out, Stderr: stderr}
			if err := validateCIRoot(dir, plan, root); err == nil {
				t.Fatal("bare exit-zero receipt replaced actual terminals")
			}
		})
	}
}

func TestCIRejectsHiddenScopeAndUnknownJSON(t *testing.T) {
	cfg := ciFixtureConfig(t, "package fixture\nimport \"testing\"\nfunc TestGiant(t *testing.T) {}\n")
	for _, flags := range [][]string{{"-run=."}, {"-skip=."}, {"-coverprofile=x"}, {"-overlay=x"}, {"-modfile=x"}, {"-gcflags=all=@x"}, {"-asmflags=all=@x"}, {"-ldflags=@x"}} {
		cfg.Flags = flags
		cfg.Out = filepath.Join(t.TempDir(), "invalid")
		if _, err := ciPrepare(cfg); err == nil {
			t.Fatal("hidden selector accepted", flags)
		}
	}
	path := filepath.Join(t.TempDir(), "unknown.json")
	for _, text := range []string{`{"unexpected":true}`, `{} {}`} {
		os.WriteFile(path, []byte(text), 0600)
		var report ciReport
		if err := ciReadJSON(path, &report); err == nil {
			t.Fatal("unknown/trailing JSON accepted")
		}
	}
	if !reflect.DeepEqual(testCIPlan().Selected, []string{"TestAlpha", "TestBeta", "TestGiant"}) || strings.Contains(testCIPlan().Selector, "/") {
		t.Fatal("fixture drift")
	}
}
