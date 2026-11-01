package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestX86VectorTestDeadNativeReadsKeepExactOpcodesAndFeatures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			declarations.WriteString("package deadvector\n")
			word, suffix := goWordSize(target.arch), "Q"
			if word == 4 {
				suffix = "L"
			}
			for index, row := range x86VectorTestInputRows() {
				ins := x86ScalarLaneInstruction(t, row)
				want := "+avx"
				if strings.HasPrefix(row, "PTEST") {
					want = "+sse4.1"
				}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, target.arch, Func{Instrs: []Instr{ins}}); got != want {
					t.Fatal("isolated native vector test borrowed sibling ISA features", row, got, want)
				}
				move, bank := "MOVUPS", "X"
				if strings.HasSuffix(row, "Y1") {
					move, bank = "VMOVUPS", "Y"
				}
				name := fmt.Sprint("Dead", index)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s input+0(FP),SI\n"+
					"MOV%s old+%d(FP),BX\n%s (BX),%s1\n%s\nRET\n",
					name, 2*word, suffix, suffix, word, move, bank, row)
				fmt.Fprintf(&declarations, "func %s(input,old *[32]byte)\n", name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
				if err != nil {
					t.Fatal("initialized dead memory effects lost their actual incoming pointers", api, err)
				}
				// Original MOVUPS input producers retain their own native
				// instructions and SSE feature; do not count them as PTESTs.
				tests := regexp.MustCompile(`asm sideeffect "(?:v?ptest|vtestpd|vtestps) `)
				if len(tests.FindAllString(ir, -1)) != 7 || !strings.Contains(ir, "+sse4.1") ||
					!strings.Contains(ir, "+avx") || strings.Contains(ir, "+avx2") {
					t.Fatal("native vector-test opcode or minimal carrier features lost", api)
				}
				for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					file := filepath.Join(t.TempDir(), "dead.ll")
					if err := os.WriteFile(file, []byte(input), 0600); err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						ctx, cancel := runtimeOracleStageContext(t)
						command := exec.CommandContext(ctx, llc, level, "-mtriple="+target.triple, "-filetype=asm", file, "-o", "-")
						output, err := runtimeOracleCombinedOutput(ctx, command)
						cancel()
						if err != nil {
							t.Fatal("complete dead vector-test native assembly", err, string(output))
						}
						for _, op := range []struct {
							name  string
							count int
						}{{"ptest", 1}, {"vptest", 2}, {"vtestpd", 2}, {"vtestps", 2}} {
							pattern := regexp.MustCompile(`(?m)^\s+` + op.name + `\s+[^\n]*\(`)
							if got := len(pattern.FindAll(output, -1)); got != op.count {
								t.Fatal("dead full-width source instruction disappeared or duplicated", api, level, op.name, got)
							}
						}
					}
				}
			}
		})
	}
}
