package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MOVNTIOriginalNativeStoresFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		for _, width := range []struct {
			suffix, typ, move string
			bytes             int
		}{
			{"L", "uint32", "MOVL", 4}, {"Q", "uint64", "MOVQ", 8},
		} {
			if target.arch == "386" && width.bytes == 8 {
				continue // Stock Go rejects Q in mode32; the separate rejection matrix owns it.
			}
			t.Run(target.triple+"/"+width.suffix, func(t *testing.T) {
				declaration := fmt.Sprintf("func Value(out *byte,value %s)\n", width.typ)
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DX\n%s value+%d(FP),AX\nMOVL $1,CX\nMOVNTI%s AX,-1(DX)(CX*2)\nMOVNTI%s AX,-1(DX)(CX*2)\nSFENCE\nMOVB $0,-1(DX)(CX*2)\nRET\n",
					word+width.bytes, move, width.move, word, width.suffix, width.suffix)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatal("initialized original MOVNTI source rejected", err)
						}
						for _, input := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							if strings.Count(input, `asm sideeffect "movnti`) != 2 || strings.Contains(input, "!nontemporal") {
								t.Fatal("native cache policy/dead writes became optional metadata or disappeared")
							}
							compileLLVMToObject(t, llc, target.triple, "movnti-native.ll", "movnti-native.o", input)
						}
					})
				}
			})
		}
	}
}

func TestX86MOVNTIDeadStoresStillRequireValueAndAddress(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move, word := "MOVQ", 8
		if target.arch == "386" {
			move, word = "MOVL", 4
		}
		for _, suffix := range []string{"L", "Q"} {
			if target.arch == "386" && suffix == "Q" {
				continue
			}
			for _, unused := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused-bool=%t", target.triple, suffix, unused), func(t *testing.T) {
					declaration, extent := "func Value(out *byte)", word
					if unused {
						declaration, extent = "func Value(out *byte,unused bool)", word+1
					}
					for _, setup := range []string{move + " out+0(FP),DX\n", "MOVL $1,AX\n"} {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOVNTI%s AX,(DX)\nRET\n", extent, setup, suffix)
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void or unused bool invented MOVNTI inputs", api, err)
							}
						}
					}
				})
			}
		}
	}
}
