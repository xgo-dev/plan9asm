package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestX86ResultGPSIMDSparseOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("five-target GP/X source/object counterpart requires LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			ops := []string{"MOVL", "MOVQ", "MOVD", "MOVDQ2Q", "VMOVD", "VMOVQ"}
			if target.arch == "386" {
				ops = []string{"MOVL", "VMOVD", "VMOVQ"}
			}
			fixture := x86GPSIMDSparseExecutionFixtureFor(t, target.arch, ops)
			positive := x86LEAActualTargetGoObject(t, target.arch, target.triple, fixture.positive)
			negative := x86LEAActualTargetGoObject(t, target.arch, target.triple, fixture.negative)
			if positive.Source == negative.Source || positive.Object == negative.Object {
				t.Fatal("independent positive/unknown files borrowed one original object")
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, fixture.positive, fixture.declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete byte/GP-X source lost its original target", err)
					}
					for _, optimizeIR := range []bool{false, true} {
						input := ir
						if optimizeIR {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimizeIR, level), func(t *testing.T) {
								// The existing owned object driver checks the actual
								// command and a nonempty regular target artifact.
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
					badIR, err := x86ScalarFPBitViewAPI(t, fixture.negative, fixture.declarations, target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || badIR != "" {
						t.Fatal("complete original unknown-return file published LLVM", err)
					}
				})
			}
		})
	}
}
