package plan9asm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/llvm"
)

// Custom FuncSig.Attrs may suppress optional source-feature inference, but
// cannot make an emitted native count intrinsic executable without SVE. Merge
// the actual LLVM attribute, including referenced groups, rather than appending
// a duplicate textual key or replacing other caller-selected features.
func completeARM64SVECountFeatures(module llvm.Module) error {
	callers := make(map[llvm.Value]bool)
	for _, suffix := range []string{"b", "h", "w", "d"} {
		intrinsic := module.NamedFunction("llvm.aarch64.sve.cnt" + suffix)
		if intrinsic.IsNil() {
			continue
		}
		for use := intrinsic.FirstUse(); !use.IsNil(); use = use.NextUse() {
			instruction := use.User().IsAInstruction()
			if !instruction.IsNil() {
				callers[instruction.InstructionParent().Parent()] = true
			}
		}
	}
	for function := module.FirstFunction(); !function.IsNil(); function = llvm.NextFunction(function) {
		if !callers[function] {
			continue
		}
		features, hasSVE := "", false
		for _, attribute := range function.GetFunctionAttributes() {
			if attribute.IsString() && attribute.GetStringKind() == "target-features" {
				features = attribute.GetStringValue()
			}
		}
		for _, feature := range strings.Split(features, ",") {
			switch strings.TrimSpace(feature) {
			case "-sve":
				return fmt.Errorf("%w: ARM64 count in %q conflicts with explicit -sve", ErrProbeNeedsContext, function.Name())
			case "+sve":
				hasSVE = true
			}
		}
		if !hasSVE {
			if features != "" {
				features += ","
			}
			function.AddTargetDependentFunctionAttr("target-features", features+"+sve")
		}
	}
	return nil
}
