package main

import "fmt"

// These are complete source object/native roles, not a test inventory.
// Missing roles are never synthesized: the actual Go list still determines
// every executed root. Fixed domains keep ownership independent of input
// order, unrelated roots and subset queries. Other names retain their hash.
func completeObjectFamilyOwners(shards int) map[string]int {
	owners := make(map[string]int)
	ordinal := 0
	for _, family := range []struct {
		prefix, suffix string
		roles          []string
		batches        int
	}{
		{"TestGoAMD64FixedLocalConversionActualObjects", "", []string{"Linux", "Darwin", "Windows"}, 12},
		{"TestGoAMD64FixedLocalPackedCompleteFormsActualObjects", "", []string{"Linux", "Darwin", "Windows"}, 4},
		{"TestX86CMOVFamilyFixedLocalAUTOActualObjects", "", []string{"Linux", "Darwin"}, 6},
		{"TestGoAMD64FixedLocalReadonlyData", "RegisteredConsumers", []string{"Linux", "Darwin", "Windows"}, 0},
		{"TestGoAMD64FixedLocalPackedWideRuntimeOracle", "CompileOnly", []string{"", "Module", "GoModule"}, 0},
		{"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWide", "", []string{""}, 6},
		{"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNative", "", []string{""}, 7},
		{"TestGoX86NumericalReadRevokeDuringFinalSDKCallback", "", []string{""}, 0},
		{"TestARM64GPImmediateScratchCompleteObjects", "", []string{""}, 0},
	} {
		for _, role := range family.roles {
			if family.batches == 0 {
				owners[family.prefix+role+family.suffix] = ordinal % shards
				ordinal++
				continue
			}
			for batch := 0; batch < family.batches; batch++ {
				name := fmt.Sprintf("%s%sBatch%02d", family.prefix, role, batch)
				owners[name] = ordinal % shards
				ordinal++
			}
		}
	}
	return owners
}
