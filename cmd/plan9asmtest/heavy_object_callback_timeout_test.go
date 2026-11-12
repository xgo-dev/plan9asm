package main

import "testing"

func TestHeavyObjectSchedulingSeparatesCompleteCallbackAndScratchOwners(t *testing.T) {
	// In race shard 31 these complete roots passed in 1380.06, 907.30 and
	// 543.21 seconds, leaving too little of the unchanged one-hour budget
	// for its ordinary roots. Preserve every API, case and object target.
	witnesses := []string{
		"TestGoX86NumericalReadRevokeDuringFinalSDKCallback",
		"TestGoAMD64FixedLocalConversionActualObjectsWindowsBatch07",
		"TestARM64GPImmediateScratchCompleteObjects",
	}
	for _, flags := range [][]string{nil, {"-cover", "-covermode=atomic"}, {"-race"}} {
		for _, count := range []int{32, 64} {
			shards, err := partitionForFlags(witnesses, count, flags)
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for index, roots := range shards {
				if len(roots) > 1 {
					t.Errorf("complete callback/scratch owners collide: flags=%v shards=%d owner=%d roots=%v", flags, count, index, roots)
				}
				for _, name := range roots {
					if seen[name] {
						t.Fatal("duplicate complete owner", name)
					}
					seen[name] = true
				}
			}
			if len(seen) != len(witnesses) {
				t.Fatal("scheduling dropped complete callback or scratch checks", flags, count)
			}
		}
	}
}
