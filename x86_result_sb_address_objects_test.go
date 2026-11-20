package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86LEASBUnknownAddressOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			widths := []string{"W", "L"}
			registers := []string{"AX", "CX", "DX", "BX", "SI", "DI", "BP"}
			if target.arch == "amd64" {
				widths = append(widths, "Q")
				registers = []string{"AX", "CX", "DX", "BX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"}
			}
			var source, declarations strings.Builder
			source.WriteString("DATA ·table<>+0(SB)/8,$7\nGLOBL ·table<>(SB),16,$16\n")
			for _, width := range widths {
				for _, register := range registers {
					name := "address" + width + register
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nMOVL $1,AX\nCMPL AX,$1\nLEA%s ·table<>-1(SB),%s\nSETEQ CL\nMOVL $7,ret+0(FP)\nRET\n", name, width, register)
					fmt.Fprintf(&declarations, "func %s() uint32\n", name)
				}
			}
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("complete W/L/Q SB address banks: TEXTs=%d source=%x object=%x SDK=%s", len(widths)*len(registers), receipt.Source, receipt.Object, receipt.GoVersion)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatalf("complete original SB source %s: %v", api, err)
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
