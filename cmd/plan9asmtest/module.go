package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const moduleProtocol = "actual_go_complete_module_v1"
const moduleRootPartsProtocol = "actual_go_complete_module_root_parts_v2"
const moduleOwners = 3

type modulePackage struct {
	Package     string `json:"package"`
	Directory   string `json:"directory"`
	NoTestFiles bool   `json:"no_test_files"`
}

type moduleResult struct {
	Package      string `json:"package"`
	Shards       int    `json:"shards"`
	Workers      int    `json:"workers"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	RootSkipped  int    `json:"root_skipped"`
	ChildSkipped int    `json:"subtests_seeds_skipped"`
	// Only populated by this invocation's complete raw-artifact verifier.
	// Serialized summaries cannot supply coverage inputs to a later reader.
	rootCoverage []string
}

type moduleReport struct {
	Protocol       string               `json:"protocol"`
	Go             string               `json:"go_executable"`
	Directory      string               `json:"request_directory"`
	Flags          []string             `json:"go_flags"`
	Coverage       string               `json:"coverage_destination"`
	Timeout        string               `json:"command_timeout"`
	Shards         int                  `json:"partition_count"`
	Workers        int                  `json:"workers"`
	Owner          int                  `json:"owner"`
	RootPartitions int                  `json:"root_partition_count,omitempty"`
	RootPartition  *int                 `json:"root_partition_index,omitempty"`
	RootInventory  *moduleRootInventory `json:"fresh_root_inventory,omitempty"`
	Scope          ciScope              `json:"scope"`
	Inventory      []modulePackage      `json:"full_package_inventory"`
	Packages       []moduleResult       `json:"packages"`
	Status         string               `json:"status"`
	Error          string               `json:"error,omitempty"`
}

// Build-selection flags are identical to test. Coverage is test instrumentation,
// not package selection; go list does not accept covermode/coverpkg.
func moduleListFlags(flags []string) []string {
	var out []string
	for i := 0; i < len(flags); i++ {
		name, _, value := strings.Cut(strings.TrimPrefix(flags[i], "-"), "=")
		if name == "cover" || name == "covermode" || name == "coverpkg" {
			if !value && name != "cover" {
				i++
			}
			continue
		}
		out = append(out, flags[i])
	}
	return out
}

func readModulePackages(data []byte, dir string) ([]modulePackage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var packages []modulePackage
	seen := map[string]bool{}
	modulePath := ""
	for {
		var pkg struct {
			ImportPath, Dir           string
			TestGoFiles, XTestGoFiles []string
			Error                     json.RawMessage
			DepsErrors                []json.RawMessage
			Module                    *struct {
				Path, Dir, GoMod string
				Main             bool
			}
		}
		err := decoder.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if pkg.Module == nil || !pkg.Module.Main || pkg.Error != nil || len(pkg.DepsErrors) != 0 ||
			pkg.Module.Dir != dir || pkg.Module.GoMod != filepath.Join(dir, "go.mod") ||
			pkg.ImportPath == "" || seen[pkg.ImportPath] {
			return nil, fmt.Errorf("invalid/foreign/duplicate actual module package: %s", pkg.ImportPath)
		}
		if modulePath == "" {
			modulePath = pkg.Module.Path
		}
		if pkg.Module.Path != modulePath || pkg.ImportPath != modulePath && !strings.HasPrefix(pkg.ImportPath, modulePath+"/") {
			return nil, fmt.Errorf("actual package is outside selected main module")
		}
		relative, err := filepath.Rel(dir, pkg.Dir)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("actual package directory escapes main module")
		}
		seen[pkg.ImportPath] = true
		packages = append(packages, modulePackage{pkg.ImportPath, filepath.ToSlash(relative), len(pkg.TestGoFiles)+len(pkg.XTestGoFiles) == 0})
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("empty actual module package inventory")
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].Package < packages[j].Package })
	return packages, nil
}

func observeModulePackages(ctx context.Context, cfg config, stem string) ([]modulePackage, error) {
	flags, _, err := validateFlags(cfg.Flags)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list"}, moduleListFlags(flags)...)
	args = append(args, "-json", "./...")
	if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, args, stem); err != nil {
		return nil, fmt.Errorf("actual complete module package list: %w", err)
	}
	data, err := os.ReadFile(stem + ".stdout")
	if err != nil {
		return nil, err
	}
	return readModulePackages(data, cfg.Dir)
}

// These are scheduling roles, not package admissions. Every actual package is
// owned once, including any future package which joins the rest owner.
func moduleOwner(pkg modulePackage) int {
	if pkg.Directory == "." {
		return 0
	}
	if pkg.Directory == "gotoolprofile" || pkg.Directory == "internal/sdkfrontend" {
		return 1
	}
	return 2
}

func modulePackageConfig(cfg config, pkg modulePackage, index int) config {
	child := cfg
	child.Package = pkg.Package
	child.Out = filepath.Join(cfg.Out, fmt.Sprintf("package-%04d", index))
	child.fullPackage = moduleOwner(pkg) == 2 || pkg.NoTestFiles
	child.noTestFiles = pkg.NoTestFiles
	if pkg.Directory == "." && cfg.ModuleRootPartitions > 1 && cfg.ModuleOwner == 0 {
		child.rootPart = &moduleRootPart{moduleRootFragmentProtocol, cfg.ModuleRootPartition, cfg.ModuleRootPartitions}
	}
	if child.fullPackage {
		child.Shards, child.Workers = 1, 1
	}
	flags, profile, _ := validateFlags(cfg.Flags)
	child.Flags = flags
	if profile != "" {
		name := "package.cover"
		if child.rootPart != nil {
			name = "partition.cover"
		}
		child.Flags = append(child.Flags, "-coverprofile="+filepath.Join(child.Out, name))
	}
	return child
}

func runModule(ctx context.Context, cfg config) error {
	// Preserve existing internal zero-value callers; the CLI has explicit
	// defaults and checks its requested values before dispatch.
	if cfg.ModuleRootPartitions == 0 && cfg.ModuleRootPartition == 0 {
		cfg.ModuleRootPartitions, cfg.ModuleRootPartition = 1, -1
	}
	if err := validateModuleRootScheduling(cfg); err != nil {
		return err
	}
	if !cfg.Module || cfg.Package != "." || cfg.CISelector != "" || cfg.CIIsolate != "" || cfg.CIVerify != "" || cfg.CIOwner != -1 ||
		cfg.Timeout <= 0 || cfg.Shards < 1 || cfg.Shards > 1024 || cfg.Workers < 1 || cfg.Workers > 32 || cfg.Workers > cfg.Shards ||
		cfg.ModuleOwner < -1 || cfg.ModuleOwner >= moduleOwners {
		return fmt.Errorf("module mode requires exhaustive '.', valid bounded scheduling and no selected-CI options")
	}
	if err := validateRunnerGoFlags(runtime.GOOS, os.Getenv("GOFLAGS"), cfg.Flags); err != nil {
		return err
	}
	if cfg.ModuleVerify != "" && cfg.ModuleOwner != -1 {
		return fmt.Errorf("module aggregate cannot also execute an owner")
	}
	flags, coverage, err := validateFlags(cfg.Flags)
	if err != nil {
		return err
	}
	for _, flag := range flags {
		name, _, _ := strings.Cut(flag, "=")
		switch name {
		case "-overlay", "-modfile", "-gcflags", "-asmflags", "-ldflags":
			return fmt.Errorf("module external compiler inputs are not source-indexed: %s", name)
		}
	}
	cfg.Go, err = exec.LookPath(cfg.Go)
	if err != nil {
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
	cfg.Dir, err = sourcepath.Resolve(cfg.Dir)
	if err != nil {
		return err
	}
	cfg.Out, err = filepath.Abs(cfg.Out)
	if err != nil {
		return err
	}
	if coverage != "" && (cfg.ModuleOwner == -1 || cfg.ModuleVerify != "") {
		destination := moduleCoverageDestination(cfg, coverage)
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			return fmt.Errorf("module coverage destination must not exist: %v", err)
		}
	}
	if err := os.Mkdir(cfg.Out, 0755); err != nil {
		return err
	}
	report := moduleReport{Protocol: moduleProtocol, Go: cfg.Go, Directory: cfg.Dir, Flags: flags, Coverage: coverage,
		Timeout: cfg.Timeout.String(), Shards: cfg.Shards, Workers: cfg.Workers, Owner: cfg.ModuleOwner, Status: "failed"}
	if cfg.ModuleRootPartitions > 1 {
		report.Protocol, report.RootPartitions = moduleRootPartsProtocol, cfg.ModuleRootPartitions
		if cfg.ModuleOwner == 0 {
			part := cfg.ModuleRootPartition
			report.RootPartition = &part
		}
	}
	finish := func(cause error) error {
		if cause != nil {
			report.Error = cause.Error()
		}
		return errors.Join(cause, ciWriteJSON(filepath.Join(cfg.Out, "module.json"), report))
	}
	report.Scope, err = captureCIScope(ctx, cfg, filepath.Join(cfg.Out, "before"))
	if err != nil {
		return finish(err)
	}
	report.Inventory, err = observeModulePackages(ctx, cfg, filepath.Join(cfg.Out, "packages-before"))
	if err != nil {
		return finish(err)
	}
	if cfg.ModuleVerify != "" {
		if report.RootPartitions > 1 {
			report.RootInventory, err = observeModuleRootInventory(ctx, cfg, report.Inventory)
			if err != nil {
				return finish(err)
			}
		}
		report.Packages, err = checkedModuleArtifacts(report, cfg.ModuleVerify)
		if err != nil && report.RootPartitions == 0 {
			return finish(err)
		}
	} else if cfg.ModuleOwner == 2 {
		err = runModuleOtherPackages(ctx, cfg, &report)
	} else {
		var failures []error
		for i, pkg := range report.Inventory {
			if cfg.ModuleOwner != -1 && moduleOwner(pkg) != cfg.ModuleOwner {
				continue
			}
			result, packageErr := runModulePackage(ctx, cfg, pkg, i)
			failures = append(failures, packageErr)
			report.Packages = append(report.Packages, result)
			if err := ciWriteJSON(filepath.Join(cfg.Out, "module.json"), report); err != nil {
				failures = append(failures, err)
			}
		}
		err = errors.Join(failures...)
	}
	postPackages, packagesErr := observeModulePackages(ctx, cfg, filepath.Join(cfg.Out, "packages-after"))
	postScope, scopeErr := captureCIScope(ctx, cfg, filepath.Join(cfg.Out, "after"))
	if packagesErr != nil || scopeErr != nil || !reflect.DeepEqual(postPackages, report.Inventory) || !reflect.DeepEqual(postScope, report.Scope) {
		err = errors.Join(err, packagesErr, scopeErr, fmt.Errorf("complete module/source/SDK/tools/environment changed"))
	}
	if cfg.ModuleVerify == "" {
		// Aggregate from the independent actual list and raw events even when
		// execution failed. Report success is never a substitute for terminals.
		err = errors.Join(err, verifyModuleOwner(report, cfg.Out))
	}
	if err != nil {
		return finish(err)
	}
	if cfg.ModuleVerify != "" && coverage != "" {
		if err := writeVerifiedModuleCoverage(report, cfg.ModuleVerify, cfg.Out, moduleCoverageDestination(cfg, coverage)); err != nil {
			return finish(err)
		}
	} else if coverage != "" && len(report.Packages) != 0 && report.RootPartition == nil {
		profile := filepath.Join(cfg.Out, "owner.cover")
		if cfg.ModuleOwner == -1 {
			profile = moduleCoverageDestination(cfg, coverage)
		}
		if err := writeModuleCoverage(report, cfg.Out, profile); err != nil {
			return finish(err)
		}
	}
	report.Status = moduleCompletionStatus(report)
	return finish(nil)
}

func runModulePackage(ctx context.Context, cfg config, pkg modulePackage, index int) (moduleResult, error) {
	child := modulePackageConfig(cfg, pkg, index)
	result := moduleResult{Package: pkg.Package, Shards: child.Shards, Workers: child.Workers, Status: "passed"}
	var failures []error
	if err := runSuite(ctx, child); err != nil {
		result.Status, result.Error = "failed", err.Error()
		failures = append(failures, fmt.Errorf("package %s: %w", pkg.Package, err))
	}
	var suite suiteReport
	if err := ciReadJSON(filepath.Join(child.Out, suiteReportName(child)), &suite); err != nil {
		result.Status, result.Error = "failed", errors.Join(errors.New(result.Error), err).Error()
		failures = append(failures, err)
	} else {
		result.RootSkipped, result.ChildSkipped = suite.RootSkipped, suite.ChildSkipped
		result.Shards, result.Workers = len(suite.Shards), suite.Workers
		if result.Status == "passed" && child.rootPart != nil {
			result.Status = suiteCompletionStatus(suite)
		}
	}
	return result, errors.Join(failures...)
}

func moduleCompletionStatus(report moduleReport) string {
	status := "passed"
	if report.RootPartition != nil {
		status = "completed_owned"
		if len(report.Packages) == 1 && report.Packages[0].Status == "completed_empty" {
			status = "completed_empty"
		}
	}
	for _, pkg := range report.Packages {
		if pkg.RootSkipped != 0 || pkg.ChildSkipped != 0 {
			if report.RootPartition != nil {
				return status + "_with_skips"
			}
			return "completed_with_skips"
		}
	}
	return status
}

func moduleCoverageDestination(cfg config, coverage string) string {
	if filepath.IsAbs(coverage) {
		return coverage
	}
	return filepath.Join(cfg.Dir, coverage)
}
