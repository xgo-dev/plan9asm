package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ExplicitMaskMoveIndependentLogicalFieldObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("explicit mask move value-field objects require LLVM22 llc")
	}
	var source, declarations strings.Builder
	for _, row := range x86ExplicitMaskMoveIndependentCases() {
		name := row.name + "Fields"
		fmt.Fprintf(&declarations, "func %s(data,mask [4]uint64)(a,b,c,d uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-96\nVMOVDQU data+0(FP),Y0\nVMOVDQU mask+32(FP),%s1\n", name, row.bank)
		instruction := strings.Replace(row.instruction, "(AX)", "data+0(FP)", 1)
		if row.memory == 2 {
			source.WriteString("VPXOR Y3,Y3,Y3\nVMOVDQU Y3,a+64(FP)\n")
			instruction = strings.Replace(row.instruction, "(AX)", "a+64(FP)", 1)
		}
		source.WriteString(instruction + "\n")
		if row.memory == 0 {
			source.WriteString("VMOVDQU Y2,a+64(FP)\n")
		}
		source.WriteString("RET\n")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete independent logical fields were treated as contiguous native FP backing", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}
