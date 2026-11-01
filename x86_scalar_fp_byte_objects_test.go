package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86ScalarFPByteCompleteFixture(arch string) (string, string, int) {
	var rows []x86ScalarFPTupleSpanCase
	for _, read := range []bool{false, true} {
		for _, row := range x86ScalarFPTupleSpanCases(arch, read) {
			rows = append(rows, row)
			if arch == "amd64" && strings.Contains(row.source, "MOVQ") {
				for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
					copy := row
					copy.source = strings.ReplaceAll(row.source, "MOVQ", alias)
					rows = append(rows, copy)
				}
			}
		}
	}
	rows = append(rows, x86ScalarFPInteriorCases(arch)...)
	for _, row := range x86ScalarFPByteInputCases(arch) {
		rows = append(rows, row.x86ScalarFPTupleSpanCase)
	}
	rows = append(rows, x86ScalarFPSparseCompleteCase, x86ScalarFPTupleSpanCase{
		declaration: "func Value() (uint8,uint8,uint8,uint8,bool)", source: x86IntegerFPByteStatusSource,
	})
	var declarations, source strings.Builder
	declarations.WriteString("package bitspan\n")
	for index, row := range rows {
		name := fmt.Sprintf("Span%d", index)
		declarations.WriteString(strings.ReplaceAll(row.declaration, "Value", name) + "\n")
		source.WriteString(strings.ReplaceAll(row.source, "Value", name))
	}
	return declarations.String(), source.String(), len(rows)
}

func TestX86IntegerFPByteViewsFiveTargetOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete integer FP byte-view objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			declarations, source, count := x86ScalarFPByteCompleteFixture(target.arch)
			wantCount := 89
			if target.arch == "386" {
				wantCount = 39
			}
			if count != wantCount || strings.Count(source, "TEXT ·") != count {
				t.Fatalf("complete unfiltered byte-view source changed: got %d, want %d", count, wantCount)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			pkg := mustGoPackage(t, "bitspan", declarations)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != count {
						t.Fatal("complete byte-view fixture failed", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}
