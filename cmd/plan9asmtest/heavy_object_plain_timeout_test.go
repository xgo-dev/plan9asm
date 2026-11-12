package main

import "testing"

func TestHeavyObjectSchedulingPlainAndCoverageBudgetCollision(t *testing.T) {
	families := heavyObjectSourceFamilies(t)
	names := heavyObjectNames(families)
	// These completed roots consumed 2251.41 seconds in one plain Go 1.20
	// shard before its unchanged 2700-second deadline. The active min/max
	// root had run for under a minute; missing later roots had never started.
	witnesses := []string{
		"TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch00",
		"TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch10",
		"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch03",
		"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch02",
		"TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsDarwinBatch01",
		"TestGoAMD64FixedLocalPackedCompleteFormsActualObjectsWindowsBatch02",
		"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch05",
	}
	for _, name := range witnesses {
		if _, found := families[name]; !found || independentHashShard(name, 32) != 20 {
			t.Fatal("original plain-shard collision witness changed", name)
		}
	}
	for _, flags := range [][]string{nil, {"-cover", "-covermode=atomic"}, {"-race=false"}, {"-race"}} {
		for _, count := range []int{32, 64} {
			shards, err := partitionForFlags(names, count, flags)
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for index, roots := range shards {
				if len(roots) < len(names)/count || len(roots) > (len(names)+count-1)/count {
					t.Errorf("complete heavy families collide: flags=%v shards=%d owner=%d roots=%v", flags, count, index, roots)
				}
				for _, name := range roots {
					if seen[name] {
						t.Fatal("duplicate source owner", name)
					}
					seen[name] = true
				}
			}
			if len(seen) != len(names) {
				t.Fatal("scheduling dropped complete sources", flags, count)
			}
		}
	}
}
