package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86X87HardwareControlCaptureOriginalGoAndLLVMFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			result := 8
			if target.arch == "386" {
				result = 4
			}
			var source, declarations strings.Builder
			for index, kind := range []string{"entry-result", "entry-param", "load-result", "load-param"} {
				name := fmt.Sprintf("Capture%d", index)
				declaration := "func Value(input uint16) uint16"
				_, _, _, original := x86ResultInitializationFixture(t, target.arch, declaration, x86X87HardwareCaptureBody(kind, result))
				source.WriteString(strings.ReplaceAll(original, "·Value(SB)", "·"+name+"(SB)"))
				declarations.WriteString(strings.Replace(declaration, "Value", name, 1) + "\n")
			}
			if strings.Count(source.String(), "TEXT ") != 4 {
				t.Fatal("complete source word-capture inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, mode := range []X87Mode{X87Auto, X87Hardware} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("mode%d/%s", mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source.String(), declarations.String(), target.arch, target.triple, api, mode)
						if err != nil || ir == "" {
							t.Fatal("complete hardware word-capture source did not translate", err)
						}
						for _, optimized := range []bool{false, true} {
							input := ir
							if optimized {
								input = x86MulDivRoundOptimize(t, input)
							}
							x86X87HardwareWordRead(t, input, 4)
							for _, backend := range []string{"-O0", "-O2"} {
								t.Run(fmt.Sprintf("IR-O2-%t/backend%s", optimized, backend), func(t *testing.T) {
									x86PackedStringCompileObject(t, llc, target.triple, input, backend)
								})
							}
						}
					})
				}
			}
		})
	}
}
