package main

import "fmt"

const moduleRootFragmentProtocol = "actual_go_root_shard_fragment_v1"

func validateModuleReportScheduling(report moduleReport) error {
	if report.Protocol == moduleProtocol {
		if report.RootPartitions != 0 || report.RootPartition != nil || report.RootInventory != nil {
			return fmt.Errorf("legacy module report contains partial scheduling")
		}
		return nil
	}
	if report.Protocol != moduleRootPartsProtocol || report.RootPartitions < 2 {
		return fmt.Errorf("unknown module scheduling protocol")
	}
	if report.Owner != -1 && report.RootInventory != nil {
		return fmt.Errorf("producer report cannot supply the aggregate's fresh inventory")
	}
	cfg := config{Module: true, Package: ".", CIOwner: -1, ModuleOwner: report.Owner,
		Shards: report.Shards, ModuleRootPartitions: report.RootPartitions, ModuleRootPartition: -1}
	if report.RootPartition != nil {
		cfg.ModuleRootPartition = *report.RootPartition
	}
	if report.Owner == -1 {
		cfg.ModuleVerify = "aggregate-observation"
	}
	return validateModuleRootScheduling(cfg)
}

// This is scheduling metadata, not executable proof or native authority.
type moduleRootPart struct {
	Protocol string `json:"protocol"`
	Index    int    `json:"index"`
	Count    int    `json:"count"`
}

func (part moduleRootPart) owns(index int, fullPackage bool) bool {
	if fullPackage {
		// Actual benchmark-only/TestMain and no-test package roles execute
		// once without a filter, regardless of the requested shard count.
		return index == 0 && part.Index == 0
	}
	return index%part.Count == part.Index
}

func suiteReportName(cfg config) string {
	if cfg.rootPart != nil {
		return "partition.json"
	}
	return "report.json"
}

func suiteExpectedRoots(report suiteReport) int {
	if report.RootPart == nil {
		return len(report.Names)
	}
	count := 0
	for _, shard := range report.Shards {
		if report.RootPart.owns(shard.Index, report.FullPackage) {
			count += len(shard.Names)
		}
	}
	return count
}

func suiteCompletionStatus(report suiteReport) string {
	if report.RootPart == nil {
		return "passed"
	}
	for _, shard := range report.Shards {
		if len(shard.Command) != 0 {
			return "completed_owned"
		}
	}
	return "completed_empty"
}

// A subordinate scheduling role, never a test selector or a package admission.
// The complete module owner numbers and selected-native protocol stay intact.
func validateModuleRootScheduling(cfg config) error {
	fail := func() error {
		return fmt.Errorf("root partition scheduling requires an explicit module root part or exhaustive aggregate, with unchanged package ownership")
	}
	if cfg.ModuleRootPartitions < 1 || cfg.ModuleRootPartitions > cfg.Shards {
		return fail()
	}
	if cfg.ModuleRootPartitions == 1 {
		if cfg.ModuleRootPartition != -1 {
			return fail()
		}
		return nil
	}
	if !cfg.Module || cfg.Package != "." || cfg.CISelector != "" || cfg.CIIsolate != "" ||
		cfg.CIVerify != "" || cfg.CIOwner != -1 {
		return fail()
	}
	if cfg.ModuleVerify != "" {
		if cfg.ModuleOwner != -1 || cfg.ModuleRootPartition != -1 {
			return fail()
		}
		return nil
	}
	switch cfg.ModuleOwner {
	case 0:
		if cfg.ModuleRootPartition < 0 || cfg.ModuleRootPartition >= cfg.ModuleRootPartitions {
			return fail()
		}
	case 1, 2:
		if cfg.ModuleRootPartition != -1 {
			return fail()
		}
	default:
		return fail()
	}
	return nil
}

// Reuse the ordinary name-to-shard plan unchanged. Parts own whole global
// shard indices, so child/seed terminals cannot move between CI jobs.
func moduleRootShardParts(shards, parts int) ([][]int, error) {
	if shards < 1 || shards > 1024 || parts < 1 || parts > shards {
		return nil, fmt.Errorf("root partition scheduling requires 1..1024 shards and 1..shards parts")
	}
	result := make([][]int, parts)
	for index := 0; index < shards; index++ {
		part := index % parts
		result[part] = append(result[part], index)
	}
	return result, nil
}
