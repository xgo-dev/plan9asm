package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

// Only the explicit remaining-package owner may overlap whole packages.
// Root/profile/default module execution retains its original scheduling. Each
// package still executes one unfiltered suite with one shard and one worker.
func runModuleOtherPackages(ctx context.Context, cfg config, report *moduleReport) error {
	if cfg.ModuleOwner != 2 {
		return fmt.Errorf("whole-package workers require the explicit remaining-package owner")
	}
	type execution struct {
		result moduleResult
		err    error
		done   bool
	}
	slots := make([]execution, len(report.Inventory))
	positions := make(map[int]int)
	var plan []shardResult
	for index, pkg := range report.Inventory {
		if moduleOwner(pkg) != 2 {
			continue
		}
		positions[index] = len(report.Packages)
		report.Packages = append(report.Packages, moduleResult{
			Package: pkg.Package, Shards: 1, Workers: 1, Status: "pending",
		})
		// Reuse only the existing bounded task/owned-process collector. These
		// indices address whole packages; no synthetic shard receipt is emitted.
		plan = append(plan, shardResult{Index: index, Status: "pending"})
	}
	if err := ciWriteJSON(filepath.Join(cfg.Out, "module.json"), report); err != nil {
		return err
	}
	err := runShardWorkers(ctx, cfg.Workers, plan,
		func(ctx context.Context, task shardResult) shardResult {
			result, err := runModulePackage(ctx, cfg, report.Inventory[task.Index], task.Index)
			// Each executor owns one distinct slot. Publication through the
			// worker's result channel precedes the collector's read of that slot.
			slots[task.Index] = execution{result, err, true}
			return task
		}, func(task shardResult) error {
			report.Packages[positions[task.Index]] = slots[task.Index].result
			return ciWriteJSON(filepath.Join(cfg.Out, "module.json"), report)
		})
	// runShardWorkers has joined all executors, including commands cancelled
	// before channel publication. Only now read their remaining slots. Never
	// dispatched packages retain pending, rather than acquiring passing credit.
	var failures []error
	for _, task := range plan {
		if slot := slots[task.Index]; slot.done {
			report.Packages[positions[task.Index]] = slot.result
			failures = append(failures, slot.err)
		}
	}
	return errors.Join(append(failures, err)...)
}
