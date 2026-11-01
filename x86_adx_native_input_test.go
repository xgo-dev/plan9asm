package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ADXDeadNativeReadsKeepExactWidthAndInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if word == 4 && strings.HasSuffix(op, "Q") {
				continue
			}
			bits := 32
			if strings.HasSuffix(op, "Q") {
				bits = 64
			}
			for _, raw := range []bool{false, true} {
				line := op + " 3(AX)(DX*2),BX"
				if raw {
					line = x86RawNumericalInstruction(t, target.arch, line)
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\nMOVL $7,BX\nCMPL BX,BX\n%s\nRET\n", word, move, line)
				variants := []struct{ name, source string }{
					{"initialized", source},
					{"unknown-address", strings.Replace(source, move+" p+0(FP),AX", move+" p+0(FP),DI", 1)},
					{"numerical-address", strings.Replace(source, move+" p+0(FP),AX", "MOVL $1,AX", 1)},
					{"unknown-index", strings.Replace(source, "MOVL $1,DX\n", "", 1)},
					{"unknown-destination", strings.Replace(source, "MOVL $7,BX\nCMPL BX,BX", "MOVL $7,CX\nCMPL CX,CX", 1)},
					{"unknown-carry", strings.Replace(source, "CMPL BX,BX\n", "", 1)},
				}
				for _, variant := range variants {
					t.Run(fmt.Sprintf("%s/%s/raw=%t/%s", target.triple, op, raw, variant.name), func(t *testing.T) {
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, variant.source, "func Value(p *[16]byte)", target.arch, target.triple, api)
							if variant.name != "initialized" {
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("dead ADX borrowed an unknown native input", api, err)
								}
								continue
							}
							if err != nil {
								t.Fatal("initialized dead native source rejected", api, err)
							}
							for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								if strings.Count(text, fmt.Sprintf("load volatile i%d,", bits)) != 1 || !strings.Contains(text, ", align 1") || strings.Contains(text, "dereferenceable") {
									t.Fatal("dead native ADX lost its exact unaligned volatile read", api)
								}
							}
						}
					})
				}
			}
		}
	}
}
