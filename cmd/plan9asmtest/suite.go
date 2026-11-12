package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type config struct {
	Go, Dir, Package, Out string
	Shards                int
	Workers               int
	Timeout               time.Duration
	Flags                 []string
	CISelector, CIIsolate string
	CIOwner               int
	CIVerify              string
	Module                bool
	ModuleVerify          string
	ModuleOwner           int
	ModuleRootPartitions  int
	ModuleRootPartition   int
	// Only the module orchestrator sets these from actual package metadata.
	fullPackage, noTestFiles bool
	rootPart                 *moduleRootPart
}

type shardResult struct {
	Index    int               `json:"index"`
	Names    []string          `json:"planned"`
	Command  []string          `json:"command,omitempty"`
	Outcomes map[string]string `json:"outcomes,omitempty"`
	Seconds  float64           `json:"seconds"`
	Status   string            `json:"status"`
	Error    string            `json:"error,omitempty"`
}

type suiteReport struct {
	Schema       int             `json:"schema"`
	Go           string          `json:"go_executable"`
	GoVersion    string          `json:"go_version"`
	Package      string          `json:"package"`
	Flags        []string        `json:"go_flags"`
	Timeout      string          `json:"command_timeout"`
	Workers      int             `json:"workers"`
	Names        []string        `json:"inventory"`
	Benchmarks   []string        `json:"benchmarks_not_run_by_default_go_test,omitempty"`
	InventorySHA string          `json:"inventory_sha256"`
	Shards       []shardResult   `json:"shards"`
	RootPassed   int             `json:"root_passed"`
	RootSkipped  int             `json:"root_skipped"`
	RootFailed   int             `json:"root_failed"`
	RootMissing  int             `json:"root_incomplete"`
	ChildPassed  int             `json:"subtests_seeds_passed"`
	ChildSkipped int             `json:"subtests_seeds_skipped"`
	ChildFailed  int             `json:"subtests_seeds_failed"`
	ChildMissing int             `json:"subtests_seeds_incomplete"`
	Status       string          `json:"status"`
	Error        string          `json:"error,omitempty"`
	FullPackage  bool            `json:"full_package,omitempty"`
	NoTestFiles  bool            `json:"no_test_files,omitempty"`
	ArtifactDir  string          `json:"artifact_directory,omitempty"`
	RootPart     *moduleRootPart `json:"root_partition,omitempty"`
}

func runSuite(ctx context.Context, cfg config) error {
	if cfg.rootPart != nil && (!cfg.Module || cfg.rootPart.Protocol != moduleRootFragmentProtocol ||
		cfg.rootPart.Count < 2 || cfg.rootPart.Count > 1024 || cfg.rootPart.Index < 0 || cfg.rootPart.Index >= cfg.rootPart.Count ||
		cfg.rootPart.Count != cfg.ModuleRootPartitions || cfg.rootPart.Index != cfg.ModuleRootPartition) {
		return fmt.Errorf("root partition scheduling requires its exact module role")
	}
	if err := validateRunnerGoFlags(runtime.GOOS, os.Getenv("GOFLAGS"), cfg.Flags); err != nil {
		return err
	}
	if cfg.Timeout <= 0 || cfg.Package == "" || strings.ContainsAny(cfg.Package, " \t\r\n*?[") || strings.Contains(cfg.Package, "...") {
		return fmt.Errorf("positive timeout and one exact package required")
	}
	// Existing programmatic callers use the zero-value config. The CLI has
	// an explicit default of one and rejects an explicitly requested zero.
	if cfg.Workers == 0 {
		cfg.Workers = 1
	}
	if cfg.Workers < 1 || cfg.Workers > 32 || cfg.Workers > cfg.Shards {
		return fmt.Errorf("workers must be 1..32 and no more than shards")
	}
	forwarded, profile, err := validateFlags(cfg.Flags)
	if err != nil {
		return err
	}
	if profile != "" {
		forwarded = append(forwarded, "-cover")
	}
	if cfg.Go, err = exec.LookPath(cfg.Go); err != nil {
		return err
	}
	cfg.Go, err = filepath.Abs(cfg.Go)
	if err != nil {
		return err
	}
	cfg.Dir, err = filepath.Abs(cfg.Dir)
	if err != nil {
		return err
	}
	cfg.Out, err = filepath.Abs(cfg.Out)
	if err != nil {
		return err
	}
	if profile != "" {
		if !filepath.IsAbs(profile) {
			profile = filepath.Join(cfg.Dir, profile)
		}
		if _, err := os.Lstat(profile); !os.IsNotExist(err) {
			return fmt.Errorf("coverage destination must not exist: %s (%v)", profile, err)
		}
	}
	if err := os.Mkdir(cfg.Out, 0755); err != nil {
		return fmt.Errorf("artifact directory must be new (parent must exist): %w", err)
	}
	report := suiteReport{Schema: 1, Go: cfg.Go, Flags: forwarded, Timeout: cfg.Timeout.String(), Workers: cfg.Workers, Status: "failed", FullPackage: cfg.fullPackage, NoTestFiles: cfg.noTestFiles}
	if cfg.rootPart != nil {
		part := *cfg.rootPart
		report.Schema, report.RootPart = 2, &part
	}
	if cfg.Module {
		report.ArtifactDir = cfg.Out
	}
	publish := func() error {
		report.RootMissing = suiteExpectedRoots(report) - report.RootPassed - report.RootSkipped - report.RootFailed
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(cfg.Out, suiteReportName(cfg)), append(data, '\n'), 0600)
	}
	fail := func(err error) error {
		report.Error = err.Error()
		return errors.Join(err, publish())
	}
	command := func(stem string, args []string) error {
		_, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, args, filepath.Join(cfg.Out, stem))
		return err
	}
	if err := command("version", []string{"version"}); err != nil {
		return fail(err)
	}
	version, err := os.ReadFile(filepath.Join(cfg.Out, "version.stdout"))
	if err != nil {
		return fail(err)
	}
	report.GoVersion = strings.TrimSpace(string(version))
	listArgs := append([]string{"test"}, forwarded...)
	listArgs = append(listArgs, "-count=1", "-timeout="+cfg.Timeout.String(), "-list=.", cfg.Package)
	if err := command("inventory", listArgs); err != nil {
		return fail(fmt.Errorf("actual Go inventory failed: %w", err))
	}
	listing, err := os.ReadFile(filepath.Join(cfg.Out, "inventory.stdout"))
	if err != nil {
		return fail(err)
	}
	report.Package, report.Names, report.Benchmarks, err = parseSuiteList(string(listing), cfg.Module || cfg.fullPackage, cfg.noTestFiles)
	if err != nil {
		return fail(err)
	}
	if cfg.Module && len(report.Names) == 0 {
		// A benchmark-only package (including a root) still executes TestMain
		// and ordinary go test without a filter. It cannot become an empty shard.
		cfg.fullPackage, cfg.Shards, cfg.Workers = true, 1, 1
		report.FullPackage, report.Workers = true, 1
	}
	shards := [][]string{report.Names}
	if !cfg.fullPackage {
		shards, err = partitionForFlags(report.Names, cfg.Shards, forwarded)
		if err != nil {
			return fail(err)
		}
	}
	hash := sha256.Sum256([]byte(strings.Join(report.Names, "\n") + "\n"))
	report.InventorySHA = hex.EncodeToString(hash[:])
	for i, names := range shards {
		result := shardResult{Index: i, Names: names, Status: "pending"}
		if cfg.rootPart != nil && !cfg.rootPart.owns(i, cfg.fullPackage) {
			result.Status = "not_owned"
		} else if len(names) == 0 && !cfg.fullPackage {
			result.Status = "empty"
		} else {
			result.Command = append([]string{cfg.Go, "test"}, forwarded...)
			if profile != "" {
				result.Command = append(result.Command, "-coverprofile="+filepath.Join(cfg.Out, fmt.Sprintf("shard-%04d.cover", i)))
			}
			result.Command = append(result.Command, "-count=1", "-timeout="+cfg.Timeout.String(), "-json")
			if !cfg.fullPackage {
				pattern, err := runPattern(names)
				if err != nil {
					return fail(err)
				}
				result.Command = append(result.Command, "-run="+pattern)
			}
			result.Command = append(result.Command, cfg.Package)
		}
		report.Shards = append(report.Shards, result)
	}
	if err := publish(); err != nil {
		return err
	}
	var failures []error
	var profiles []string
	// Workers receive immutable plan values. Only this collector updates the
	// report, counters and coverage inventory; there are no concurrent writes.
	plan := append([]shardResult(nil), report.Shards...)
	if cfg.rootPart != nil {
		plan = nil
		for _, shard := range report.Shards {
			if cfg.rootPart.owns(shard.Index, cfg.fullPackage) {
				plan = append(plan, shard)
			}
		}
	}
	err = runShardWorkers(ctx, cfg.Workers, plan, func(ctx context.Context, result shardResult) shardResult {
		return executeShard(ctx, cfg, report.Package, result)
	}, func(result shardResult) error {
		report.Shards[result.Index] = result
		if result.Status != "passed" {
			failures = append(failures, fmt.Errorf("shard %d: %s", result.Index, result.Error))
		}
		for name, state := range result.Outcomes {
			child := strings.Contains(name, "/")
			switch state {
			case "pass":
				if child {
					report.ChildPassed++
				} else {
					report.RootPassed++
				}
			case "skip":
				if child {
					report.ChildSkipped++
				} else {
					report.RootSkipped++
				}
			case "fail":
				if child {
					report.ChildFailed++
				} else {
					report.RootFailed++
				}
			case "run":
				if child {
					report.ChildMissing++
				}
			}
		}
		if profile != "" {
			profiles = append(profiles, filepath.Join(cfg.Out, fmt.Sprintf("shard-%04d.cover", result.Index)))
		}
		fmt.Printf("shard %d/%d: %s (%d roots, %.3fs)\n", result.Index+1, len(shards), result.Status, len(result.Names), result.Seconds)
		return publish()
	})
	if err != nil {
		return fail(errors.Join(errors.Join(failures...), err))
	}
	if len(failures) != 0 {
		return fail(errors.Join(failures...))
	}
	if profile != "" && (cfg.rootPart == nil || len(profiles) != 0) {
		merged, err := mergeCoverage(profiles)
		if err != nil {
			return fail(err)
		}
		file, err := os.OpenFile(profile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fail(err)
		}
		_, writeErr := file.Write(merged)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return fail(err)
		}
	}
	report.Status = suiteCompletionStatus(report)
	label := "complete root inventory"
	if cfg.rootPart != nil {
		label = "complete owned root assignment (partial package)"
	}
	fmt.Printf("%s: %d passed, %d skipped, %d failed; subtests/seeds: %d passed, %d skipped, %d failed\n", label, report.RootPassed, report.RootSkipped, report.RootFailed, report.ChildPassed, report.ChildSkipped, report.ChildFailed)
	return publish()
}

func executeShard(ctx context.Context, cfg config, pkg string, result shardResult) shardResult {
	stem := filepath.Join(cfg.Out, fmt.Sprintf("shard-%04d", result.Index))
	seconds, executionErr := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, result.Command[1:], stem)
	result.Seconds = seconds
	var validationErr error
	file, openErr := os.Open(stem + ".stdout")
	if openErr == nil {
		result.Outcomes, validationErr = validateSuiteEvents(file, pkg, result.Names, cfg.fullPackage, cfg.noTestFiles)
		validationErr = errors.Join(validationErr, file.Close())
	} else {
		validationErr = openErr
	}
	if err := errors.Join(executionErr, validationErr); err != nil {
		result.Status, result.Error = "failed", err.Error()
	} else {
		result.Status = "passed"
	}
	return result
}

type boundedOutput struct {
	mu        sync.Mutex
	Remaining int64
	Cancel    context.CancelFunc
	Err       error
}

type outputWriter struct {
	File  *os.File
	Bound *boundedOutput
}

func (writer outputWriter) Write(data []byte) (int, error) {
	writer.Bound.mu.Lock()
	defer writer.Bound.mu.Unlock()
	if int64(len(data)) > writer.Bound.Remaining {
		writer.Bound.Err = fmt.Errorf("command output exceeds 64 MiB capture bound")
		writer.Bound.Cancel()
		return 0, writer.Bound.Err
	}
	n, err := writer.File.Write(data)
	writer.Bound.Remaining -= int64(n)
	return n, err
}

func captureCommand(parent context.Context, timeout time.Duration, dir, executable string, args []string, stem string) (float64, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	out, err := os.OpenFile(stem+".stdout", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	errOut, err := os.OpenFile(stem+".stderr", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	defer errOut.Close()
	bound := &boundedOutput{Remaining: 64 << 20, Cancel: cancel}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir, cmd.WaitDelay = dir, 2*time.Second
	cmd.Stdout, cmd.Stderr = outputWriter{out, bound}, outputWriter{errOut, bound}
	started := time.Now()
	err = runOwnedCommand(cmd)
	err = errors.Join(err, ctx.Err(), bound.Err, out.Close(), errOut.Close())
	return time.Since(started).Seconds(), err
}

var _ io.Writer = outputWriter{}
