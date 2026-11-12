package plan9asm

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// CMOV reads bits, including NaN payloads and the sign bit of zero. A complete
// declared floating field is numerical storage, not pointer/frame authority.
func TestX86CMOVFamilyFPBitViewsThreeAPIFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86OrderingHintTargets {
		for _, typ := range []string{"float32", "float64"} {
			for _, width := range []string{"W", "L", "Q"} {
				if target.arch == "386" && width == "Q" || typ == "float32" && width == "Q" {
					continue
				}
				var assembly strings.Builder
				for _, condition := range x86CMOVOracleConditions {
					fmt.Fprintf(&assembly, "CMOV%s%s f+0(FP),AX\n", width, condition.name)
				}
				size := map[string]int{"float32": 4, "float64": 8}[typ]
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sRET\n", size, assembly.String())
				goAssemblerOracleOutput(t, target.arch, source, "", true)
				initialized := strings.Replace(source, "\nCMOV", "\nXORL AX,AX\nCMOV", 1)
				goAssemblerOracleOutput(t, target.arch, initialized, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+typ+"/"+width+"/"+api, func(t *testing.T) {
						ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\nfunc Value(f "+typ+")\n", target.arch, target.triple)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("original FP formats invented old AX or predicate FLAGS", api, err)
						}
						ir, err = x86OrderingHintTranslateAPI(t, api, initialized, "package ordering\nfunc Value(f "+typ+")\n", target.arch, target.triple)
						if err != nil {
							t.Fatal("existing complete floating logical bit-view was lost", err)
						}
						if x86CMOVFPHasNumericConversion(ir) {
							t.Fatal("raw FP bytes were numerically converted")
						}
						compileLLVMToObject(t, llc, target.triple, "cmov-fp-"+api+".ll", "cmov-fp-"+api+".o", ir)
					})
				}
			}
		}
	}
}

func TestX86CMOVFamilyFPBitViewsExactPartialAndCrossSlotExtent(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, target := range x86OrderingHintTargets {
		for _, test := range []struct {
			declaration, width, source string
			size                       int
			valid                      bool
		}{
			{"func Value(f float32)", "W", "f+2(FP)", 4, true},
			{"func Value(f float64)", "L", "f+4(FP)", 8, true},
			{"func Value(f float32)", "L", "f+1(FP)", 4, false},
			{"func Value(f float64)", "Q", "f+1(FP)", 8, false},
			{"func Value(f float32,g float32)", "Q", "f+0(FP)", 8, true},
			{"func Value(f float32,g float32)", "L", "f+2(FP)", 8, true},
			{"func Value(f float32,g uint32)", "Q", "f+0(FP)", 8, true},
			{"func Value(f float32,g uint64)", "Q", "f+0(FP)", 16, false},
			{"func Value(f float32,g *uint32)", "Q", "f+0(FP)", 16, false},
			{"func Value(f *float64)", "Q", "f+0(FP)", 8, false},
		} {
			if target.arch == "386" && test.width == "Q" {
				continue
			}
			source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nCMOV%sLE %s,AX\nRET\n", test.size, test.width, test.source)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			initialized := strings.Replace(source, "\nCMOV", "\nXORL AX,AX\nCMOV", 1)
			goAssemblerOracleOutput(t, target.arch, initialized, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+test.declaration+"/"+test.width+"/"+test.source+"/"+api, func(t *testing.T) {
					ir, err := x86OrderingHintTranslateAPI(t, api, source, "package ordering\n"+test.declaration+"\n", target.arch, target.triple)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original partial FP format invented old AX or predicate FLAGS", api, err)
					}
					ir, err = x86OrderingHintTranslateAPI(t, api, initialized, "package ordering\n"+test.declaration+"\n", target.arch, target.triple)
					if test.valid && err != nil || !test.valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("complete bit span/holes/Ptr contract", err)
					}
					if test.valid && x86CMOVFPHasNumericConversion(ir) {
						t.Fatal("FP byte reconstruction became a numerical conversion")
					}
					if test.valid {
						compileLLVMToObject(t, llc, target.triple, "cmov-fp-span-"+api+".ll", "cmov-fp-span-"+api+".o", ir)
					}
				})
			}
		}
	}
}

// Common intrinsic declarations are not executed conversion instructions.
func x86CMOVFPHasNumericConversion(ir string) bool {
	return regexp.MustCompile(`(?m)^\s+%[^\n]+ = (fptosi|fptoui|call [^\n]*@llvm\.fpto(si|ui))`).MatchString(ir)
}
