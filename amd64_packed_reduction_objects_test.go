package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86PackedReductionInitializedFixture(name, arch, instruction string, destination int) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s p+0(FP),BX\n"+
		"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\nSTC\n%s\nVMOVDQU64 Z%d,(AX)\nSETCS 64(AX)\nRET\n",
		name, word, move, move, instruction, destination), "func " + name + "(p *byte)\n"
}

func TestX86PackedReductionCompleteInitializedNamedRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86PackedReductionOracleRows()
	raw := x86PackedReductionOriginalRawRows(t, rows)
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, spelling := range []string{"named", "raw"} {
				t.Run(spelling, func(t *testing.T) {
					var source, declarations strings.Builder
					count := 0
					for index, row := range rows {
						if target.arch == "386" && spelling == "named" && row.dot && !row.legacy {
							continue
						}
						instruction := row.row
						if spelling == "raw" {
							instruction = raw[index]
						}
						destination := 1
						if !row.legacy {
							destination = 2
						}
						body, declaration := x86PackedReductionInitializedFixture(fmt.Sprintf("Reduction%d", index), target.arch, instruction, destination)
						source.WriteString(body)
						declarations.WriteString(declaration)
						count++
					}
					if count != 34 && !(target.arch == "386" && spelling == "named" && count == 28) {
						t.Fatal("complete reduction source matrix lost rows", count)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil {
								t.Fatal("complete initialized reduction source rejected", err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							for _, pipeline := range []struct{ name, ir, backend string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									if strings.Count(pipeline.ir, "asm sideeffect") != count || strings.Count(pipeline.ir, "~{fpsr}") != count ||
										strings.Contains(pipeline.ir, "call <4 x float> @llvm.x86.sse41.dpps") ||
										strings.Contains(pipeline.ir, "@__plan9asm_add_sub_special") {
										t.Fatal("reduction lost whole native arithmetic/MXCSR effects or retained replaced software helpers")
									}
									x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.backend)
								})
							}
						})
					}
				})
			}
		})
	}
}
