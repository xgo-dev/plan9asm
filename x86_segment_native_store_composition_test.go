package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86SegmentLoadAndNativeStoreHaveIndependentPairedEffects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range x86SegmentMOVRows(target.arch) {
			for _, segment := range []string{"FS", "GS"} {
				declaration := "func view(offset uintptr,p *byte) " + row.result
				// Preserve the complete original former caller-write negative.
				// Reading a native value does not grant a write: the separate
				// paired GP store requires the actual incoming p identity.
				body := fmt.Sprintf("%s p+%d(FP),DI\n%s 24(%s),DX\n%s DX,(DI)\n%s $7,ret+RESULT(FP)", move, word, row.op, segment, row.store, row.store)
				source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.op+"/"+segment+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" || !strings.Contains(ir, "load volatile ") || !strings.Contains(ir, "store volatile ") {
							t.Fatal("composed segment load/native store lost a complete effect", err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
						// Objects do not establish physical FS/GS runtime state.
					})
				}
			}
		}
	}
}
