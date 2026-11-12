package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86MXCSRBoundMemoryFormsOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range x86MXCSRBoundMemoryForms(t, target.arch) {
				name := fmt.Sprintf("mxcsrBound%d", index)
				original := strings.Replace(row.source, "·view(SB)", "·"+name+"(SB)", 1)
				// Each whole original function retains its own DATA definition,
				// without overlapping another function's control word.
				original = strings.ReplaceAll(original, "control<>", fmt.Sprintf("control%d<>", index))
				source.WriteString(original)
				declarations.WriteString(strings.Replace(row.declaration, "func view(", "func "+name+"(", 1))
				declarations.WriteByte('\n')
			}
			file, err := Parse(ArchAMD64, source.String())
			if err != nil || len(file.Funcs) != 10 || len(file.Data) != 2 || len(file.Globl) != 2 {
				t.Fatal("complete ten-function/two-DATA original batch differs", err)
			}
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("complete original bound MXCSR source: TEXTs=10 DATA=2 source=%x object=%x SDK=%s",
				receipt.Source, receipt.Object, receipt.GoVersion)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || strings.Count(ir, "define ") != 10 {
					t.Fatalf("complete typed MXCSR batch %s: %v", api, err)
				}
				for _, irLevel := range []string{"0", "2"} {
					objectIR := ir
					if irLevel == "2" {
						objectIR = x86DwordProductIROptimize(t, ir)
					}
					for _, backendLevel := range []string{"0", "2"} {
						t.Run(api+"/IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, target.triple, objectIR, "-O"+backendLevel)
						})
					}
				}
			}
		})
	}
}
