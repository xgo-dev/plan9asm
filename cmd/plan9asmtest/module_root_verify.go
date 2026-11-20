package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

type moduleRootInventory struct {
	Package      string   `json:"package"`
	Names        []string `json:"inventory"`
	Benchmarks   []string `json:"benchmarks_not_executed"`
	InventorySHA string   `json:"inventory_sha256"`
	NoTestFiles  bool     `json:"no_test_files"`
	FullPackage  bool     `json:"full_package"`
}

func moduleRootPackage(packages []modulePackage) (modulePackage, int, error) {
	for index, pkg := range packages {
		if pkg.Directory == "." {
			return pkg, index, nil
		}
	}
	return modulePackage{}, 0, fmt.Errorf("split module requires an actual root package")
}

// The aggregate obtains its own complete root list, rather than accepting a
// producer's stored list/hash as the denominator. No test roots execute here.
func observeModuleRootInventory(ctx context.Context, cfg config, packages []modulePackage) (*moduleRootInventory, error) {
	pkg, _, err := moduleRootPackage(packages)
	if err != nil {
		return nil, err
	}
	flags, profile, err := validateFlags(cfg.Flags)
	if err != nil {
		return nil, err
	}
	if profile != "" {
		flags = append(flags, "-cover")
	}
	args := append([]string{"test"}, flags...)
	args = append(args, "-count=1", "-timeout="+cfg.Timeout.String(), "-list=.", pkg.Package)
	stem := filepath.Join(cfg.Out, "root-inventory")
	if _, err := captureCommand(ctx, cfg.Timeout, cfg.Dir, cfg.Go, args, stem); err != nil {
		return nil, fmt.Errorf("fresh actual complete root list: %w", err)
	}
	data, err := os.ReadFile(stem + ".stdout")
	if err != nil {
		return nil, err
	}
	actual, names, benchmarks, err := parseSuiteList(string(data), true, pkg.NoTestFiles)
	if err != nil || actual != pkg.Package {
		return nil, fmt.Errorf("fresh actual complete root inventory differs: %v", err)
	}
	return &moduleRootInventory{actual, names, benchmarks, ciNamesSHA(names), pkg.NoTestFiles,
		pkg.NoTestFiles || len(names) == 0}, nil
}

func exactModuleArtifactDirectories(directory string, wanted []string) error {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(wanted) {
		return fmt.Errorf("missing/extra module scheduling directories: %v", err)
	}
	for index, name := range wanted {
		if entries[index].Name() != name {
			return fmt.Errorf("unknown module scheduling directory: %s", entries[index].Name())
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("module scheduling directory is not a physical directory: %v", err)
		}
	}
	return nil
}

func checkedSplitModuleArtifacts(expected moduleReport, directory string) ([]moduleResult, error) {
	if expected.Owner != -1 || expected.RootPartition != nil || expected.RootInventory == nil {
		return nil, fmt.Errorf("split aggregate requires its own fresh complete root inventory")
	}
	if err := exactModuleArtifactDirectories(directory, []string{"owner-0000", "owner-0001", "owner-0002"}); err != nil {
		return nil, err
	}
	root, err := checkedModuleRootParts(expected, filepath.Join(directory, "owner-0000"))
	if err != nil {
		return nil, err
	}
	completed := map[string]moduleResult{root.Package: root}
	for owner := 1; owner < moduleOwners; owner++ {
		path := filepath.Join(directory, fmt.Sprintf("owner-%04d", owner))
		var actual moduleReport
		if err := ciReadJSON(filepath.Join(path, "module.json"), &actual); err != nil {
			return nil, err
		}
		wanted := expected
		wanted.Owner, wanted.RootInventory = owner, nil
		if !sameModulePlan(actual, wanted) || actual.Status != moduleCompletionStatus(actual) || actual.Error != "" {
			return nil, fmt.Errorf("module owner %d has foreign/failed/incomplete split plan", owner)
		}
		if err := verifyModuleOwner(actual, path); err != nil {
			return nil, fmt.Errorf("module owner %d: %w", owner, err)
		}
		for _, result := range actual.Packages {
			if _, duplicate := completed[result.Package]; duplicate {
				return nil, fmt.Errorf("package assigned to multiple module scheduling owners")
			}
			completed[result.Package] = result
		}
	}
	var results []moduleResult
	for _, pkg := range expected.Inventory {
		result, exists := completed[pkg.Package]
		if !exists {
			return nil, fmt.Errorf("package has no complete scheduling owner")
		}
		results = append(results, result)
	}
	return results, nil
}

func checkedModuleRootParts(expected moduleReport, directory string) (moduleResult, error) {
	fresh := expected.RootInventory
	pkg, packageIndex, err := moduleRootPackage(expected.Inventory)
	if err != nil || fresh == nil || fresh.Package != pkg.Package || fresh.NoTestFiles != pkg.NoTestFiles ||
		fresh.InventorySHA != ciNamesSHA(fresh.Names) || fresh.FullPackage != (pkg.NoTestFiles || len(fresh.Names) == 0) {
		return moduleResult{}, fmt.Errorf("fresh root denominator is missing/inconsistent: %v", err)
	}
	plan := [][]string{fresh.Names}
	if !fresh.FullPackage {
		plan, err = partitionForFlags(fresh.Names, expected.Shards, expected.Flags)
		if err != nil {
			return moduleResult{}, err
		}
	}
	directories := make([]string, expected.RootPartitions)
	for index := range directories {
		directories[index] = fmt.Sprintf("part-%04d", index)
	}
	if err := exactModuleArtifactDirectories(directory, directories); err != nil {
		return moduleResult{}, err
	}
	result := moduleResult{Package: pkg.Package, Shards: len(plan), Workers: expected.Workers, Status: "passed"}
	if fresh.FullPackage {
		result.Workers = 1
	}
	seenShards := make([]bool, len(plan))
	seenTerminals := make(map[string]bool)
	for part := 0; part < expected.RootPartitions; part++ {
		path := filepath.Join(directory, directories[part])
		var actual moduleReport
		if err := ciReadJSON(filepath.Join(path, "module.json"), &actual); err != nil {
			return moduleResult{}, err
		}
		wanted := expected
		wanted.Owner, wanted.RootPartition, wanted.RootInventory = 0, &part, nil
		if !sameModulePlan(actual, wanted) || actual.Status != moduleCompletionStatus(actual) || actual.Error != "" {
			return moduleResult{}, fmt.Errorf("root part %d has foreign/failed/incomplete plan", part)
		}
		packagePath := filepath.Join(path, fmt.Sprintf("package-%04d", packageIndex))
		var suite suiteReport
		if err := ciReadJSON(filepath.Join(packagePath, "partition.json"), &suite); err != nil {
			return moduleResult{}, err
		}
		if !reflect.DeepEqual(suite.Names, fresh.Names) || !reflect.DeepEqual(suite.Benchmarks, fresh.Benchmarks) ||
			suite.InventorySHA != fresh.InventorySHA || suite.FullPackage != fresh.FullPackage || suite.NoTestFiles != fresh.NoTestFiles ||
			len(suite.Shards) != len(plan) {
			return moduleResult{}, fmt.Errorf("root part %d differs from fresh complete root denominator", part)
		}
		if err := verifyModuleOwner(actual, path); err != nil {
			return moduleResult{}, fmt.Errorf("root part %d: %w", part, err)
		}
		result.RootSkipped += suite.RootSkipped
		result.ChildSkipped += suite.ChildSkipped
		for index, shard := range suite.Shards {
			if !suite.RootPart.owns(index, fresh.FullPackage) {
				continue
			}
			if seenShards[index] || shard.Index != index || !reflect.DeepEqual(shard.Names, plan[index]) {
				return moduleResult{}, fmt.Errorf("duplicate/foreign global root shard %d", index)
			}
			seenShards[index] = true
			for name := range shard.Outcomes {
				if seenTerminals[name] {
					return moduleResult{}, fmt.Errorf("root/child terminal has multiple scheduling owners: %s", name)
				}
				seenTerminals[name] = true
			}
			if expected.Coverage != "" && len(shard.Command) != 0 {
				result.rootCoverage = append(result.rootCoverage,
					filepath.Join(packagePath, fmt.Sprintf("shard-%04d.cover", index)))
			}
		}
	}
	for index, present := range seenShards {
		if !present {
			return moduleResult{}, fmt.Errorf("global root shard %d has no complete owner", index)
		}
	}
	if expected.Coverage != "" {
		if _, err := mergeCoverage(result.rootCoverage); err != nil {
			return moduleResult{}, fmt.Errorf("complete root shard coverage differs: %w", err)
		}
	}
	return result, nil
}

func writeSplitModuleCoverage(report moduleReport, directory, outputDirectory, destination string) error {
	var paths []string
	for index, pkg := range report.Inventory {
		if pkg.Directory == "." {
			if index >= len(report.Packages) || report.Packages[index].Package != pkg.Package {
				return fmt.Errorf("checked complete root coverage result is missing")
			}
			data, err := mergeCoverage(report.Packages[index].rootCoverage)
			if err != nil {
				return err
			}
			rootPath := filepath.Join(outputDirectory, "root.cover")
			if err := writeNewCoverage(data, rootPath); err != nil {
				return err
			}
			paths = append(paths, rootPath)
		} else {
			paths = append(paths, filepath.Join(directory, fmt.Sprintf("owner-%04d", moduleOwner(pkg)),
				fmt.Sprintf("package-%04d", index), "package.cover"))
		}
	}
	return writeCoverageUnion(paths, destination)
}
