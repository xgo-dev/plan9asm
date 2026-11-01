package plan9asm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Reuse the complete unmodified native CI program, not a zero-return or
// initialized-shadow substitute. The six integer unpack rows each retain
// their actual native memory and split-FP siblings.
func TestX86MMXUnpackOriginalNativeSourceThreeAPIsThreeTargetObjects(t *testing.T) {
	source, signatures, _, _, count := x86PackedUnpackMMXNativeProgram()
	if count != 6 || len(signatures) != 12 {
		t.Fatal("complete native MMX unpack family changed", count, len(signatures))
	}
	var names []string
	for name := range signatures {
		names = append(names, name)
	}
	sort.Strings(names)
	var declarations strings.Builder
	for _, name := range names {
		parameters := "input *byte,second uint64"
		if signatures[name].Args[0] != Ptr {
			parameters = "a,b uint32"
		}
		fmt.Fprintf(&declarations, "func %s(%s) uint64\n", name, parameters)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Go's ymm Py1 named integer rows require mode64.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), "amd64", target.triple, api)
					if err != nil {
						t.Fatal("complete initialized native MMX source lacks its closed physical-state continuation", err)
					}
					if !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, "emms") {
						t.Fatal("numerical interleaving alone cannot represent physical MMX/x87 effects")
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86MMXUnpackCannotBorrowInitializedShadowOrUnclosedState(t *testing.T) {
	const declaration = "func view(input *byte,second uint64) uint64"
	const body = "MOVQ input+0(FP),AX\nMOVQ second+8(FP),M0\nPUNPCKLBW (AX),M0\nMOVQ M0,ret+16(FP)\nEMMS\nRET\n"
	for _, row := range []struct{ name, source string }{
		{"missing-MMX-data", strings.Replace(body, "MOVQ second+8(FP),M0\n", "", 1)},
		{"missing-address", strings.Replace(body, "MOVQ input+0(FP),AX\n", "", 1)},
		{"numeric-address", strings.Replace(body, "MOVQ input+0(FP),AX", "MOVQ second+8(FP),AX", 1)},
		{"unclosed-MMX-state", strings.Replace(body, "EMMS\n", "", 1)},
	} {
		source := "TEXT ·view(SB),4,$0-24\n" + row.source
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("an implementation MMX slot supplied source bytes or caller state", err)
				}
			})
		}
	}
}

func TestX86MMXVoidCannotHideInputsOrPhysicalState(t *testing.T) {
	for _, declaration := range []string{"func view()", "func view(unused bool)"} {
		args := 0
		if strings.Contains(declaration, "bool") {
			args = 1
		}
		for _, body := range []string{
			"PUNPCKLBW M1,M0\nEMMS\nRET",
			"MOVL $1,AX\nMOVL AX,M0\nRET",
			"MOVQ M0,AX\nEMMS\nRET",
		} {
			source := fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\n", args, body)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(declaration+"/"+body+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Void or unused bool hid an unknown MMX input or unclosed hardware state", err)
					}
				})
			}
		}
	}
}
