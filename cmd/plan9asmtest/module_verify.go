package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

func sameModulePlan(actual, expected moduleReport) bool {
	// Paths are artifact origins, not cross-machine identities. The complete
	// selected SDK/source/tool byte hashes and normalized environment must match.
	return actual.Protocol == expected.Protocol && actual.Owner == expected.Owner &&
		actual.RootPartitions == expected.RootPartitions && reflect.DeepEqual(actual.RootPartition, expected.RootPartition) &&
		reflect.DeepEqual(actual.Flags, expected.Flags) && actual.Coverage == expected.Coverage &&
		actual.Timeout == expected.Timeout && actual.Shards == expected.Shards && actual.Workers == expected.Workers &&
		reflect.DeepEqual(actual.Scope, expected.Scope) && reflect.DeepEqual(actual.Inventory, expected.Inventory)
}

func verifyModuleArtifacts(expected moduleReport, directory string) error {
	_, err := checkedModuleArtifacts(expected, directory)
	return err
}

func checkedModuleArtifacts(expected moduleReport, directory string) ([]moduleResult, error) {
	if err := validateModuleReportScheduling(expected); err != nil {
		return nil, err
	}
	if expected.RootPartitions > 1 {
		return checkedSplitModuleArtifacts(expected, directory)
	}
	if _, err := os.Lstat(filepath.Join(directory, "module.json")); err == nil {
		var actual moduleReport
		if err := ciReadJSON(filepath.Join(directory, "module.json"), &actual); err != nil {
			return nil, err
		}
		if actual.Owner != -1 || !sameModulePlan(actual, expected) || actual.Status != moduleCompletionStatus(actual) || actual.Error != "" {
			return nil, fmt.Errorf("complete module plan/status differs")
		}
		return actual.Packages, verifyModuleOwner(actual, directory)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != moduleOwners {
		return nil, fmt.Errorf("exactly three module owners required: %v", err)
	}
	completed := map[string]moduleResult{}
	for owner := 0; owner < moduleOwners; owner++ {
		path := filepath.Join(directory, fmt.Sprintf("owner-%04d", owner))
		var actual moduleReport
		if err := ciReadJSON(filepath.Join(path, "module.json"), &actual); err != nil {
			return nil, err
		}
		wanted := expected
		wanted.Owner = owner
		if !sameModulePlan(actual, wanted) || actual.Status != moduleCompletionStatus(actual) || actual.Error != "" {
			return nil, fmt.Errorf("module owner %d has foreign/failed/incomplete plan", owner)
		}
		if err := verifyModuleOwner(actual, path); err != nil {
			return nil, fmt.Errorf("module owner %d: %w", owner, err)
		}
		for _, result := range actual.Packages {
			if _, duplicate := completed[result.Package]; duplicate {
				return nil, fmt.Errorf("package assigned to multiple owners")
			}
			completed[result.Package] = result
		}
	}
	var results []moduleResult
	for _, pkg := range expected.Inventory {
		result, exists := completed[pkg.Package]
		if !exists {
			return nil, fmt.Errorf("package has no completed owner")
		}
		results = append(results, result)
	}
	return results, nil
}

func verifyModuleOwner(report moduleReport, directory string) error {
	if err := validateModuleReportScheduling(report); err != nil {
		return err
	}
	if report.Owner < -1 || report.Owner >= moduleOwners {
		return fmt.Errorf("unknown module protocol/owner")
	}
	if err := verifyScopeArtifacts(directory, report.Go, report.Scope); err != nil {
		return err
	}
	if err := verifyModuleDependencyArtifacts(directory, report); err != nil {
		return err
	}
	for _, phase := range []string{"before", "after"} {
		data, err := os.ReadFile(filepath.Join(directory, "packages-"+phase+".stdout"))
		if err != nil {
			return err
		}
		packages, err := readModulePackages(data, report.Directory)
		if err != nil || !reflect.DeepEqual(packages, report.Inventory) {
			return fmt.Errorf("actual %s package inventory differs: %v", phase, err)
		}
		var environment ciEnvironmentContext
		if err := ciReadJSON(filepath.Join(directory, phase+"-environment-context.json"), &environment); err != nil || environment.Directory != report.Directory {
			return fmt.Errorf("actual module CWD differs: %v", err)
		}
	}
	var wanted []modulePackage
	for _, pkg := range report.Inventory {
		if report.Owner == -1 || moduleOwner(pkg) == report.Owner {
			wanted = append(wanted, pkg)
		}
	}
	if len(report.Packages) != len(wanted) {
		return fmt.Errorf("missing/extra package completion: %d/%d", len(report.Packages), len(wanted))
	}
	position := 0
	var failures []error
	for index, pkg := range report.Inventory {
		if report.Owner != -1 && moduleOwner(pkg) != report.Owner {
			continue
		}
		result := report.Packages[position]
		position++
		cfg := config{Go: report.Go, Dir: report.Directory, Out: directory, Flags: append([]string(nil), report.Flags...),
			Shards: report.Shards, Workers: report.Workers, Module: true, ModuleOwner: report.Owner,
			ModuleRootPartitions: report.RootPartitions, ModuleRootPartition: -1}
		if report.RootPartition != nil {
			cfg.ModuleRootPartition = *report.RootPartition
		}
		cfg.Timeout, _ = time.ParseDuration(report.Timeout)
		if report.Coverage != "" {
			cfg.Flags = append(cfg.Flags, "-coverprofile="+report.Coverage)
		}
		child := modulePackageConfig(cfg, pkg, index)
		listing, err := os.ReadFile(filepath.Join(child.Out, "inventory.stdout"))
		if err == nil {
			listedPackage, names, _, parseErr := parseSuiteList(string(listing), true, pkg.NoTestFiles)
			if parseErr == nil && listedPackage == pkg.Package && len(names) == 0 {
				child.fullPackage, child.Shards, child.Workers = true, 1, 1
			}
		}
		statusMatches := result.Status == "passed"
		if child.rootPart != nil {
			statusMatches = result.Status == "completed_owned" || result.Status == "completed_empty"
		}
		if result.Package != pkg.Package || result.Shards != child.Shards || result.Workers != child.Workers || !statusMatches || result.Error != "" {
			failures = append(failures, fmt.Errorf("package %s incomplete/failed: %s", pkg.Package, result.Error))
		}
		if err := verifyModulePackage(child, pkg, report.Coverage != ""); err != nil {
			failures = append(failures, fmt.Errorf("package %s: %w", pkg.Package, err))
		}
		var suite suiteReport
		if err := ciReadJSON(filepath.Join(child.Out, suiteReportName(child)), &suite); err != nil || suite.GoVersion != report.Scope.GoVersion ||
			suite.Status != result.Status ||
			suite.RootSkipped != result.RootSkipped || suite.ChildSkipped != result.ChildSkipped {
			failures = append(failures, fmt.Errorf("package version/explicit skip counters differ: %v", err))
		}
	}
	return errors.Join(failures...)
}

func verifyModulePackage(cfg config, pkg modulePackage, covered bool) error {
	var report suiteReport
	if err := ciReadJSON(filepath.Join(cfg.Out, suiteReportName(cfg)), &report); err != nil {
		return err
	}
	flags, _, err := validateFlags(cfg.Flags)
	if covered {
		flags = append(flags, "-cover")
	}
	schema := 1
	if cfg.rootPart != nil {
		schema = 2
	}
	if err != nil || report.Schema != schema || !reflect.DeepEqual(report.RootPart, cfg.rootPart) ||
		report.Status != suiteCompletionStatus(report) || report.Error != "" || report.Go != cfg.Go ||
		report.Package != pkg.Package || report.Timeout != cfg.Timeout.String() || report.Workers != cfg.Workers ||
		report.FullPackage != cfg.fullPackage || report.NoTestFiles != cfg.noTestFiles || !filepath.IsAbs(report.ArtifactDir) ||
		!reflect.DeepEqual(report.Flags, flags) {
		return fmt.Errorf("per-package plan/status differs: %v", err)
	}
	listing, err := os.ReadFile(filepath.Join(cfg.Out, "inventory.stdout"))
	if err != nil {
		return err
	}
	listedPackage, names, benchmarks, err := parseSuiteList(string(listing), cfg.fullPackage, cfg.noTestFiles)
	if err != nil || listedPackage != pkg.Package || !reflect.DeepEqual(names, report.Names) ||
		!reflect.DeepEqual(benchmarks, report.Benchmarks) || report.InventorySHA != ciNamesSHA(names) {
		return fmt.Errorf("actual complete package test inventory differs: %v", err)
	}
	plan := [][]string{names}
	if !cfg.fullPackage {
		plan, err = partitionForFlags(names, cfg.Shards, flags)
		if err != nil {
			return err
		}
	}
	if len(plan) != len(report.Shards) {
		return fmt.Errorf("missing/extra shard")
	}
	counts := suiteReport{}
	var profiles []string
	for index, names := range plan {
		shard := report.Shards[index]
		if shard.Index != index || !reflect.DeepEqual(shard.Names, names) {
			return fmt.Errorf("duplicate/foreign shard assignment")
		}
		if cfg.rootPart != nil && !cfg.rootPart.owns(index, cfg.fullPackage) {
			if shard.Status != "not_owned" || len(shard.Command) != 0 || len(shard.Outcomes) != 0 || shard.Error != "" || shard.Seconds != 0 {
				return fmt.Errorf("unassigned shard gained execution or completion")
			}
			if err := verifyUnexecutedShardFiles(cfg.Out, index); err != nil {
				return err
			}
			continue
		}
		if !cfg.fullPackage && len(names) == 0 {
			if shard.Status != "empty" || len(shard.Command) != 0 || len(shard.Outcomes) != 0 || shard.Error != "" {
				return fmt.Errorf("empty shard gained execution")
			}
			if cfg.rootPart != nil {
				if err := verifyUnexecutedShardFiles(cfg.Out, index); err != nil {
					return err
				}
			}
			continue
		}
		command := append([]string{cfg.Go, "test"}, flags...)
		if covered {
			command = append(command, "-coverprofile="+filepath.Join(report.ArtifactDir, fmt.Sprintf("shard-%04d.cover", index)))
			profiles = append(profiles, filepath.Join(cfg.Out, fmt.Sprintf("shard-%04d.cover", index)))
		}
		command = append(command, "-count=1", "-timeout="+cfg.Timeout.String(), "-json")
		if !cfg.fullPackage {
			pattern, err := runPattern(names)
			if err != nil {
				return err
			}
			command = append(command, "-run="+pattern)
		}
		command = append(command, pkg.Package)
		if !reflect.DeepEqual(command, shard.Command) || shard.Status != "passed" || shard.Error != "" {
			return fmt.Errorf("actual command/flags/deadline or shard status differs")
		}
		file, err := os.Open(filepath.Join(cfg.Out, fmt.Sprintf("shard-%04d.stdout", index)))
		if err != nil {
			return err
		}
		states, validationErr := validateSuiteEvents(file, pkg.Package, names, cfg.fullPackage, cfg.noTestFiles)
		sameStates := reflect.DeepEqual(states, shard.Outcomes) || len(states) == 0 && len(shard.Outcomes) == 0
		if err := errors.Join(validationErr, file.Close()); err != nil || !sameStates {
			return fmt.Errorf("actual raw JSON/terminals differ: %v", err)
		}
		for name, state := range states {
			child := strings.Contains(name, "/")
			if state == "pass" {
				if child {
					counts.ChildPassed++
				} else {
					counts.RootPassed++
				}
			} else if state == "skip" {
				if child {
					counts.ChildSkipped++
				} else {
					counts.RootSkipped++
				}
			}
		}
	}
	if counts.RootPassed != report.RootPassed || counts.RootSkipped != report.RootSkipped || counts.ChildPassed != report.ChildPassed ||
		counts.ChildSkipped != report.ChildSkipped || report.RootFailed+report.RootMissing+report.ChildFailed+report.ChildMissing != 0 {
		return fmt.Errorf("root/child completion counters differ")
	}
	if covered {
		profile := "package.cover"
		if cfg.rootPart != nil {
			profile = "partition.cover"
		}
		if len(profiles) == 0 && cfg.rootPart != nil {
			if _, err := os.Lstat(filepath.Join(cfg.Out, profile)); !os.IsNotExist(err) {
				return fmt.Errorf("empty root fragment gained coverage: %v", err)
			}
			return nil
		}
		merged, err := mergeCoverage(profiles)
		actual, readErr := os.ReadFile(filepath.Join(cfg.Out, profile))
		if err != nil || readErr != nil || !bytes.Equal(merged, actual) {
			return fmt.Errorf("package coverage is not the complete checked shard merge: %v %v", err, readErr)
		}
	}
	return nil
}

func verifyUnexecutedShardFiles(directory string, index int) error {
	for _, suffix := range []string{".stdout", ".stderr", ".cover"} {
		path := filepath.Join(directory, fmt.Sprintf("shard-%04d%s", index, suffix))
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return fmt.Errorf("unexecuted root shard has an artifact: %v", err)
		}
	}
	return nil
}

func writeModuleCoverage(report moduleReport, directory, destination string) error {
	var paths []string
	for i, pkg := range report.Inventory {
		if report.Owner == -1 || moduleOwner(pkg) == report.Owner {
			paths = append(paths, filepath.Join(directory, fmt.Sprintf("package-%04d", i), "package.cover"))
		}
	}
	return writeCoverageUnion(paths, destination)
}

func writeVerifiedModuleCoverage(report moduleReport, directory, outputDirectory, destination string) error {
	if report.RootPartitions > 1 {
		return writeSplitModuleCoverage(report, directory, outputDirectory, destination)
	}
	if _, err := os.Lstat(filepath.Join(directory, "module.json")); err == nil {
		return writeModuleCoverage(report, directory, destination)
	}
	var paths []string
	for i, pkg := range report.Inventory {
		paths = append(paths, filepath.Join(directory, fmt.Sprintf("owner-%04d", moduleOwner(pkg)), fmt.Sprintf("package-%04d", i), "package.cover"))
	}
	return writeCoverageUnion(paths, destination)
}

func writeCoverageUnion(paths []string, destination string) error {
	data, err := mergeModuleCoverage(paths)
	if err != nil {
		return err
	}
	return writeNewCoverage(data, destination)
}

func writeNewCoverage(data []byte, destination string) error {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	info, statErr := file.Stat()
	err = errors.Join(writeErr, statErr, file.Close())
	if err != nil {
		current, currentErr := os.Lstat(destination)
		if currentErr != nil || info == nil || !os.SameFile(info, current) {
			return errors.Join(err, fmt.Errorf("failed coverage output identity changed: %v", currentErr))
		}
		return errors.Join(err, os.Remove(destination))
	}
	return nil
}
