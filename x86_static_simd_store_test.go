package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

var x86StaticSIMDStoreRows = []struct {
	op    string
	width int
}{
	{"MOVL", 4}, {"MOVQ", 8}, {"MOVD", 8}, {"MOVDQ2Q", 8},
	{"VMOVD", 4}, {"VMOVQ", 8},
}

func x86StaticSIMDStoreSource(op string) string {
	return "GLOBL slot<>(SB),16,$16\nTEXT ·view(SB),4,$0-4\nPXOR X0,X0\n" +
		op + " X0,slot<>+4(SB)\nMOVL $7,AX\nMOVL AX,ret+0(FP)\nRET\n"
}

func TestX86StaticIntegerSIMDSBStoresCompleteMoveFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete static SIMD stores require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		for _, row := range x86StaticSIMDStoreRows {
			t.Run(target.triple+"/"+row.op, func(t *testing.T) {
				source := x86StaticSIMDStoreSource(row.op)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				file, err := Parse(ArchAMD64, source)
				if err != nil || len(file.Funcs) != 1 {
					t.Fatal("complete static source did not parse", err)
				}
				// This checks routing only; a manual signature grants no source,
				// frame, memory or initialized-result permission to the APIs.
				if !x86StaticIntegerResultSourceCandidate(file.Funcs[0], FuncSig{Ret: I32}, target.arch) {
					t.Error("a typed scalar memory move escaped the complete static result route")
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
						if err != nil || !strings.Contains(ir, fmt.Sprintf("store volatile i%d", row.width*8)) {
							t.Fatal("complete initialized X source lost its exact static store", err)
						}
						for _, backend := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, backend)
						}
					})
				}
			})
		}
	}
}

func TestX86StaticIntegerSIMDSBStoresRetainInputResultAndExtentBoundaries(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range x86StaticSIMDStoreRows {
			original := x86StaticSIMDStoreSource(row.op)
			for name, source := range map[string]string{
				"unknown-source": strings.Replace(original, "PXOR X0,X0\n", "", 1),
				"missing-result": strings.Replace(original, "MOVL AX,ret+0(FP)\n", "", 1),
				"short-extent":   strings.Replace(original, "$16\n", fmt.Sprintf("$%d\n", row.width+3), 1),
				"unknown-symbol": strings.Replace(original, "X0,slot<>+4(SB)", "X0,externalSlot(SB)", 1),
			} {
				t.Run(target.triple+"/"+row.op+"/"+name, func(t *testing.T) {
					if source == original {
						t.Fatal("independent negative mutation did not change the source")
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32\n", target.arch, target.triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("static store acquired unknown bytes, storage or an independent result", err)
							}
						})
					}
				})
			}
		}
	}
}
