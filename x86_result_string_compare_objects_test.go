package plan9asm

import "testing"

func TestX86StringCompareFiveTargetThreeAPICompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86StringCompareCompleteSource(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("complete original string-comparison source was rejected", err)
				}
				for _, irLevel := range []string{"0", "2"} {
					input := ir
					if irLevel == "2" {
						input = x86DwordProductIROptimize(t, input)
					}
					for _, backendLevel := range []string{"0", "2"} {
						t.Run(api+"/IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, input, "-O"+backendLevel)
						})
					}
				}
			}
		})
	}
}
