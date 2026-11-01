package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Keep the complete former immediate-store negatives as initialized positives.
// The compare/widening read grants no write: its independent paired volatile
// store still needs both the actual pointer and known numerical source bytes.
func TestX86NativeCompareAndWideningStoresConsumeIndependentEffects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			count := 0
			for index, op := range x86ScalarCompareNames(target.arch) {
				name := fmt.Sprint("CompareStore", index)
				compare := x86ScalarCompareInstruction(op, "(DX)", "$1")
				source.WriteString(x86ScalarComparePointerSource(target.arch, name, "", compare, "MOVL $1,(DX)\n"))
				fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
				count++
			}
			if target.arch == "amd64" {
				for _, ratio := range x86ZeroExtendTestRatios {
					for _, prefix := range []string{"P", "VP"} {
						name := fmt.Sprint("WidenStore", count)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-12\nMOVQ p+0(FP),DX\n%sMOVZX%s (DX),X1\n"+
							"MOVL $1,(DX)\nPEXTRD $0,X1,AX\nMOVL AX,ret+8(FP)\nRET\n", name, prefix, ratio.suffix)
						fmt.Fprintf(&declarations, "func %s(p *[32]byte) uint32\n", name)
						count++
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("separately checked native effects failed to compose", api, err)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					if strings.Count(text, "store volatile i32 1,") != count {
						t.Fatal("a complete independent native store was lost", api)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}
