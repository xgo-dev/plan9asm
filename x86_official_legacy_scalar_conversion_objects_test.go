package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The original instruction is unchanged. NUM producers, native input pointers
// and preserved XMM bytes are supplied separately; source rows grant none.
func TestX86LegacyScalarConversionInitializedThreeAPIObjects(t *testing.T) {
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	fixtures := scalarConversion12OriginalCases(t, catalog)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			if word == 4 {
				move = "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for _, fixture := range fixtures {
				op := strings.Fields(fixture.witness.Instruction)[0]
				if target.arch == "386" && strings.Contains(op, "SQ") {
					continue
				}
				name := fmt.Sprintf("ScalarConversionObject%d", count)
				result, store, resultBytes := "uintptr", move+" BX", word
				if strings.HasSuffix(op, "SS") {
					result, store, resultBytes = "float32", "MOVSS X1", 4
				} else if strings.HasSuffix(op, "SD") {
					result, store, resultBytes = "float64", "MOVSD X1", 8
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\n%s input+%d(FP),CX\nPXOR X0,X0\nPXOR X1,X1\n%s\n%s,ret+%d(FP)\nRET\n",
					name, 2*word+resultBytes, move, move, word, fixture.witness.Instruction, store, 2*word)
				fmt.Fprintf(&declarations, "func %s(p *[8]byte,input uintptr) %s\n", name, result)
				count++
			}
			want := 24
			if target.arch == "386" {
				want = 12
			}
			if count != want || count > 32 {
				t.Fatal("initialized original conversion inventory changed", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original scalar conversion rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}
}
