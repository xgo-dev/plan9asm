package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86TernaryGPDeadNativeReadsKeepExactWidthAndInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			bits := 32
			if word == 8 && strings.HasSuffix(op, "Q") {
				bits = 64
			}
			for _, raw := range []bool{false, true} {
				line := op + " 3(AX)(DX*2),BX,CX"
				if raw {
					line = x86RawNumericalInstruction(t, target.arch, line)
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $1,DX\nMOVL $7,BX\n%s\nRET\n", word, move, line)
				variants := []struct{ name, source string }{
					{"initialized", source},
					{"unknown-address", strings.Replace(source, move+" p+0(FP),AX", move+" p+0(FP),DI", 1)},
					{"numerical-address", strings.Replace(source, move+" p+0(FP),AX", "MOVL $1,AX", 1)},
					{"unknown-index", strings.Replace(source, "MOVL $1,DX\n", "", 1)},
					{"unknown-second", strings.Replace(source, "MOVL $7,BX\n", "", 1)},
				}
				for _, variant := range variants {
					t.Run(fmt.Sprintf("%s/%s/raw=%t/%s", target.triple, op, raw, variant.name), func(t *testing.T) {
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, variant.source, "func Value(p *[16]byte)", target.arch, target.triple, api)
							if variant.name != "initialized" {
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("dead ternary GP borrowed an unknown native input", api, err)
								}
								continue
							}
							if err != nil {
								t.Fatal("initialized dead native source rejected", api, err)
							}
							for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								if strings.Count(text, fmt.Sprintf("load volatile i%d,", bits)) != 1 || !strings.Contains(text, ", align 1") || strings.Contains(text, "dereferenceable") {
									t.Fatal("dead native ternary GP lost its exact unaligned volatile read", api)
								}
							}
						}
					})
				}
			}
		}
	}
}

func TestX86TernaryGPUnusedBoolCannotHideMissingData(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			for _, raw := range []bool{false, true} {
				line := op + " AX,BX,CX"
				if raw {
					line = x86RawNumericalInstruction(t, target.arch, line)
				}
				for _, missing := range []string{"", "MOVL $7,AX\n", "MOVL $3,BX\n"} {
					source := "TEXT ·Value(SB),4,$0-1\nMOVL $7,AX\nMOVL $3,BX\n" + line + "\nRET\n"
					if missing != "" {
						source = strings.Replace(source, missing, "", 1)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(unused bool)", target.arch, target.triple, api)
						if missing == "" {
							if err != nil || ir == "" {
								t.Fatal("initialized Void/bool inputs rejected", target.triple, op, api, err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unused bool hid a missing data input", target.triple, op, api, err)
						}
					}
				}
			}
		}
	}
}
