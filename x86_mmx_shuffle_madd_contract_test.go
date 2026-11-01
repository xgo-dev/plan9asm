package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// Keep the discovering unclosed format sources in their original tests. These
// separate programs supply real FP inputs and close the hardware MMX/x87 state.
func TestX86MMXShuffleMultiplyAddCompleteSourceBoundaries(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const declaration = "func Value(a,b uint64) uint64"
	for _, target := range x86RawReturnTargets {
		for _, row := range []string{"PSHUFW $-128,M0,M1", "PMADDWL M0,M1"} {
			t.Run(target.triple+"/"+row, func(t *testing.T) {
				const inputs = "MOVQ a+0(FP),M0\nMOVQ b+8(FP),M1\n"
				const finish = "\nMOVQ M1,ret+16(FP)\nEMMS\nRET"
				body := inputs + row + finish
				_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
				if target.arch == "386" && strings.HasPrefix(row, "PMADDWL") {
					// Go's Py1 integer MMX row is mode64-only; PSHUFW's row is not.
					goAssemblerOracleOutput(t, target.arch, source, "", false)
					return
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, "emms") {
							t.Fatal("complete initialized MMX source lost its physical region", err)
						}
						for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, target.triple, text, level)
							}
						}
					})
				}
				for _, change := range []struct{ name, old, replacement string }{
					{"missing-source", "MOVQ a+0(FP),M0\n", ""},
					{"unclosed-state", "EMMS\n", ""},
					{"interleaved-state", row, "MOVL $1,AX\n" + row},
				} {
					t.Run(change.name, func(t *testing.T) {
						original := strings.Replace(source, change.old, change.replacement, 1)
						if original == source {
							t.Fatal("negative control did not change its intended source")
						}
						x86LEAActualTargetGoObject(t, target.arch, target.triple, original)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, original, declaration, target.arch, target.triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("incomplete MMX source borrowed input bytes or hardware state", api, err)
							}
						}
					})
				}
			})
		}
	}
}
