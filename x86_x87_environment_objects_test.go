package plan9asm

import "testing"

func TestX86X87ENVBoundedFiveTargetCompleteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required for the complete environment objects")
	}
	for _, target := range x86RawReturnTargets {
		source, declaration := x86X87ENVBoundedSource(), "func clearModeledStatus(env *byte) uint64"
		if target.arch == "386" {
			source, declaration = x86X87ENV386BoundedSource, "func Value(env *byte) uint32"
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, X87Software)
				if err != nil || ir == "" {
					t.Fatal("whole source did not reach the object compiler", err)
				}
				for _, level := range []string{"0", "2"} {
					input := ir
					if level == "2" {
						input = x86DwordProductIROptimize(t, input)
					}
					for _, backend := range []string{"0", "2"} {
						t.Run("IR"+level+"/backend"+backend, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, input, "-O"+backend)
						})
					}
				}
			})
		}
	}
}
