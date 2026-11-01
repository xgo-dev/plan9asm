package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MOVBEDeadNativeAccessKeepsExactWidthAndInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		for _, op := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			bits := x86MOVBEWidths[Op(op)]
			if word == 4 && bits == 64 {
				continue
			}
			for _, store := range []bool{false, true} {
				for _, raw := range []bool{false, true} {
					line, effect := op+" 3(AX)(DX*2),BX", "load"
					if store {
						line, effect = op+" BX,3(AX)(DX*2)", "store"
					}
					if raw {
						line = x86RawNumericalInstruction(t, target.arch, line)
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n"+
						"MOVL $1,DX\nMOVL $7,BX\n%s\nMOVL $0,BX\nRET\n", word, move, line)
					variants := []struct{ name, source string }{
						{"initialized", source},
						{"unknown-address", strings.Replace(source, move+" p+0(FP),AX", move+" p+0(FP),DI", 1)},
						{"numerical-address", strings.Replace(source, move+" p+0(FP),AX", "MOVL $1,AX", 1)},
						{"unknown-index", strings.Replace(source, "MOVL $1,DX\n", "", 1)},
					}
					if store {
						variants = append(variants, struct{ name, source string }{
							"unknown-value", strings.Replace(source, "MOVL $7,BX\n", "", 1),
						}, struct{ name, source string }{
							"pointer-not-value", strings.Replace(source, "MOVL $7,BX", move+" p+0(FP),BX", 1),
						})
					}
					for _, variant := range variants {
						t.Run(fmt.Sprintf("%s/%s/%s/raw=%t/%s", target.triple, op, effect, raw, variant.name), func(t *testing.T) {
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, variant.source, "func Value(p *[16]byte)", target.arch, target.triple, api)
								if variant.name != "initialized" {
									if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
										t.Fatal("dead MOVBE borrowed an unknown address or value", api, err)
									}
									continue
								}
								if err != nil {
									t.Fatal("initialized dead MOVBE native access rejected", api, err)
								}
								for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
									if strings.Count(text, fmt.Sprintf("%s volatile i%d ", effect, bits)) != 1 &&
										strings.Count(text, fmt.Sprintf("%s volatile i%d,", effect, bits)) != 1 {
										t.Fatal("dead MOVBE lost its exact volatile access", api, effect, bits)
									}
									if !strings.Contains(text, ", align 1") || strings.Contains(text, "dereferenceable") {
										t.Fatal("MOVBE invented memory alignment or backing", api)
									}
								}
								if store {
									twice := strings.Replace(variant.source, line+"\n", line+"\n"+line+"\n", 1)
									twiceIR, err := x86ScalarFPBitViewAPI(t, twice, "func Value(p *[16]byte)", target.arch, target.triple, api)
									if err != nil || strings.Count(x86DwordProductIROptimize(t, twiceIR), fmt.Sprintf("store volatile i%d ", bits)) != 2 {
										t.Fatal("overwritten MOVBE native store lost its observable access", api, err)
									}
								}
							}
						})
					}
				}
			}
		}
	}
}
