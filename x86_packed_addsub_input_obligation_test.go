package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The independent Go-row inventories cover all legacy/V add/sub spellings,
// including PADDD. Routing a Void function must retain native address/index
// obligations without borrowing an unrelated KMOV or result-store selector.
func TestX86PackedAddSubVoidNativeInputsCannotBypassWholeProof(t *testing.T) {
	names := append([]string(nil), x86LegacyIntegerArithmeticTestNames...)
	for _, member := range x86ResultVectorArithmeticNames {
		names = append(names, member.name)
	}
	if len(names) != 33 {
		t.Fatal("complete independent legacy/V add-sub inventory changed", len(names))
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
					banks = append(banks, "Y", "Z")
				}
				for _, bank := range banks {
					instruction := op + " 3(AX)(DX*2)," + bank + "1"
					if strings.HasPrefix(op, "V") {
						instruction = op + " 3(AX)(DX*2)," + bank + "0," + bank + "1"
					}
					prefix := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\n", extent, move)
					source := prefix + "VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" + instruction + "\nRET\n"
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
					// One Go object below binds every original positive/negative
					// source. Each public query still checks its own function.
					t.Run(fmt.Sprintf("%s/bool%t/%s/%s", target.triple, unusedBool, op, bank), func(t *testing.T) {
						for _, variant := range variants {
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, variant.source, declaration, target.arch, target.triple, api)
								if variant.name == "initialized" {
									if err != nil || ir == "" {
										t.Fatal("complete Void native input rejected", api, err)
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
