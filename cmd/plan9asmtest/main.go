// plan9asmtest exhaustively runs actual Go package or main-module inventories.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.Go, "go", "go", "Go executable")
	flag.StringVar(&cfg.Dir, "dir", ".", "package working directory")
	flag.StringVar(&cfg.Package, "package", ".", "one package, not a recursive pattern")
	flag.StringVar(&cfg.Out, "out", "_out/root-suite", "new, nonexisting artifact directory")
	flag.IntVar(&cfg.Shards, "shards", 32, "stable exhaustive partitions")
	flag.IntVar(&cfg.Workers, "workers", 1, "bounded ordinary-suite parallelism (1..32, no more than shards)")
	flag.DurationVar(&cfg.Timeout, "timeout", 45*time.Minute, "per-command wall deadline and Go test timeout")
	flag.StringVar(&cfg.CISelector, "ci-selector", "", "explicit selected-CI root inventory (ordinary mode remains exhaustive)")
	flag.IntVar(&cfg.CIOwner, "ci-owner", -1, "one selected-CI owner; every owned root runs separately")
	flag.StringVar(&cfg.CIIsolate, "ci-isolate-root", "", "selected root exclusively assigned to owner zero")
	flag.StringVar(&cfg.CIVerify, "verify-ci-partitions", "", "strictly verify all selected-CI owner artifacts against fresh actual inventory")
	flag.BoolVar(&cfg.Module, "module", false, "exhaustive ./... main-module inventory; partition root, profile and SDK frontend")
	flag.IntVar(&cfg.ModuleOwner, "module-owner", -1, "optional module scheduling owner: 0=root, 1=profile and SDK frontend, 2=all remaining packages")
	flag.StringVar(&cfg.ModuleVerify, "verify-module", "", "verify complete module artifacts against fresh source/tool/package observations")
	flag.IntVar(&cfg.ModuleRootPartitions, "module-root-partitions", 1, "exhaustive root shard scheduling parts; module owners only")
	flag.IntVar(&cfg.ModuleRootPartition, "module-root-partition", -1, "one root-only scheduling part; partial execution is not complete module success")
	flag.Parse()
	cfg.Flags = flag.Args()
	if err := validateModuleRootScheduling(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "plan9asmtest:", err)
		os.Exit(1)
	}
	if cfg.Workers < 1 || cfg.Workers > 32 || cfg.Workers > cfg.Shards {
		fmt.Fprintln(os.Stderr, "plan9asmtest: workers must be 1..32 and no more than shards")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), cancellationSignals()...)
	defer stop()
	var err error
	if cfg.Module || cfg.ModuleVerify != "" || cfg.ModuleOwner != -1 {
		err = runModule(ctx, cfg)
	} else if cfg.CISelector != "" || cfg.CIIsolate != "" || cfg.CIOwner != -1 || cfg.CIVerify != "" {
		err = runCI(ctx, cfg)
	} else {
		err = runSuite(ctx, cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "plan9asmtest:", err)
		os.Exit(1)
	}
}
