package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These inventories are independent of the production maps and bind the
// complete Go logical and packed EQ/GT families. A dead result cannot excuse
// an unknown native address, even without a KMOV or FP result-store selector.
func TestX86LogicalCompareVoidNativeInputsCannotBypassWholeProof(t *testing.T) {
	names := append([]string(nil), x86PackedIntegerCompareTestNames...)
	for _, group := range x86LogicalNativeGroups {
		names = append(names, group...)
	}
	if len(names) != 48 {
		t.Fatal("independent logical/compare family inventory changed", len(names))
	}
	for _, target := range x86RawReturnTargets {
		for _, unusedBool := range []bool{false, true} {
			word, move, declaration := int(goWordSize(target.arch)), "MOVQ", "func Value(p *[128]byte)"
			if word == 4 {
				move = "MOVL"
			}
			extent := word
			if unusedBool {
				declaration = "func Value(p *[128]byte, unused bool)"
				extent++
			}
			var original strings.Builder
			for ordinal, op := range names {
				banks := []string{"X"}
				if strings.HasPrefix(op, "V") {
					banks = append(banks, "Y")
					if op != "VPAND" && op != "VPANDN" && op != "VPOR" && op != "VPXOR" {
						banks = append(banks, "Z")
					}
				}
				for _, bank := range banks {
					instruction := op + " 3(AX)(DX*2)," + bank + "1"
					if strings.HasPrefix(op, "V") {
						destination := bank + "1"
						if strings.HasPrefix(op, "VPCMP") && bank == "Z" {
							destination = "K2"
						}
						instruction = op + " 3(AX)(DX*2)," + bank + "0," + destination
					}
					prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\nVZEROALL\n", extent, move)
					source := prefix + instruction + "\nRET\n"
					variants := []struct{ name, source string }{
						{"initialized", source},
						{"unknown-pointer", strings.Replace(source, move+" p+0(FP),AX", move+" p+0(FP),DI", 1)},
						{"numerical-pointer", strings.Replace(source, move+" p+0(FP),AX", "MOVL $1,AX", 1)},
						{"unknown-index", strings.Replace(source, "MOVL $1,DX\n", "", 1)},
					}
					for index, variant := range variants {
						name := fmt.Sprintf("Value%d%sCase%d", ordinal, bank, index)
						original.WriteString(strings.Replace(variant.source, "·Value(SB)", "·"+name+"(SB)", 1))
					}
					t.Run(fmt.Sprintf("%s/bool%t/%s/%s", target.triple, unusedBool, op, bank), func(t *testing.T) {
						for _, variant := range variants {
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, variant.source, declaration, target.arch, target.triple, api)
								if variant.name == "initialized" {
									if err != nil || ir == "" {
										t.Fatal("complete Void native inputs rejected", api, err)
									}
								} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Errorf("%s/%s: missing native input bypassed the whole proof: %v", variant.name, api, err)
								}
							}
						}
					})
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, original.String())
		}
	}
}
