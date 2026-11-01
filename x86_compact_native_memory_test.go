package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func x86CompactNativeFixture(arch, op, bank, mode string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	mask := ""
	if mode != "plain" {
		mask = "K1,"
	}
	if mode == "zero" {
		op += ".Z"
	}
	operation := fmt.Sprintf("%s %s0,%s1(DI)", op, bank, mask)
	if strings.Contains(op, "EXPAND") {
		operation = fmt.Sprintf("%s 1(DI),%s%s0\nVMOVDQU64 %s0,65(DI)", op, mask, bank, bank)
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),DI\nMOVL mask+%d(FP),AX\n"+
		"KMOVD AX,K1\nVPXORD Z0,Z0,Z0\n%s\nMOVL $7,AX\nMOVL AX,ret+%d(FP)\nRET\n",
		2*word+4, move, word, operation, 2*word)
	return source, "func Value(p *[128]byte, mask uint32) uint32"
}

func TestX86CompactNativeMemorySequencesThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var names []string
			for _, op := range x86CompactExpandResultMembers {
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if mode == "zero" && !strings.Contains(op, "EXPAND") {
							continue // EVEX.z memory stores are #UD, not a positive.
						}
						body, declaration := x86CompactNativeFixture(target.arch, op, bank, mode)
						name := fmt.Sprintf("Value%d", len(names))
						names = append(names, name)
						source.WriteString(strings.ReplaceAll(body, "Value", name))
						declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
					}
				}
			}
			if len(names) != 90 {
				t.Fatal("complete compact memory denominator changed", len(names))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete native compact memory sequence rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					if regexp.MustCompile(`(?m)^  (?:%[^ =]+ = )?call [^\n]*@llvm\.masked\.(?:expandload|compressstore)\.`).MatchString(ir) {
						t.Fatal("native compact access must retain observable guarded loads/stores")
					}
					for _, optimized := range []bool{false, true} {
						objectIR := ir
						if optimized {
							objectIR = x86DwordProductIROptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, objectIR, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86CompactNativeMemoryCannotInventSourceOrDestinationFacts(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, op := range x86CompactExpandResultMembers {
			for _, bank := range []string{"X", "Y", "Z"} {
				source, declaration := x86CompactNativeFixture(arch, op, bank, "merge")
				mutations := map[string]string{
					"unknown-source": strings.Replace(source, "VPXORD Z0,Z0,Z0", "NOP", 1),
					"unknown-mask":   strings.Replace(source, "KMOVD AX,K1", "NOP", 1),
					"unknown-base":   strings.ReplaceAll(source, "(DI)", "(SI)"),
					"unknown-index":  strings.ReplaceAll(source, "(DI)", "(DI)(SI*1)"),
					"pointer-index":  strings.ReplaceAll(source, "(DI)", "(DI)(DI*1)"),
					"missing-result": strings.Replace(source, "MOVL AX,ret+", "// MOVL AX,ret+", 1),
				}
				for name, source := range mutations {
					t.Run(arch+"/"+op+"/"+bank+"/"+name, func(t *testing.T) {
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							if _, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("native compact sequence acquired an unknown input/result", api, err)
							}
						}
					})
				}
			}
		}
	}
}
