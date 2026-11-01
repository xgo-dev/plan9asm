package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86LegacyNativeStoreCompletePairedNumericalFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	// Complete whole128 yxmov store namespace, including Go's MOVOA alias.
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, op := range []string{"MOVO", "MOVOA", "MOVOU", "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD"} {
			t.Run(target.triple+"/"+op, func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\nPXOR X0,X0\n%s X0,3(AX)(DX*2)\nMOVL $7,CX\nMOVL CX,ret+%d(FP)\nRET\n",
					word+4, move, op, word)
				declaration := "func Value(p *byte) uint32"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete legacy native store lost its paired numerical continuation", api, err)
					}
					if strings.Count(ir, "asm sideeffect") != 1 || !strings.Contains(ir, "~{memory}") {
						t.Fatal("original aligned/unaligned whole128 store lost its exact native effect")
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				}
				for name, changed := range map[string]string{
					"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),BX", 1),
					"unknown-index":   strings.Replace(source, "MOVL $1,DX\n", "", 1),
					"unknown-data":    strings.Replace(source, "PXOR X0,X0\n", "", 1),
					"numeric-pointer": strings.Replace(source, "MOVL $1,DX", "MOVL $42,AX\nMOVL $1,DX", 1),
				} {
					t.Run(name, func(t *testing.T) {
						for _, api := range []string{"text", "module", "Go"} {
							if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
								t.Fatal("legacy native store borrowed data/address authority", api, err)
							}
						}
					})
				}
			})
		}
	}
}
