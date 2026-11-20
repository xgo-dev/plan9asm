package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86CompareExchangeResultFullFamilyOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("the complete CAS result family requires LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			ops := []string{"CMPXCHGB", "CMPXCHGW", "CMPXCHGL", "CMPXCHG8B"}
			if target.arch == "amd64" {
				ops = append(ops, "CMPXCHGQ", "CMPXCHG16B")
			}
			var source, declarations strings.Builder
			for _, op := range ops {
				for _, shape := range []string{"plain-memory", "LOCK-memory", "register"} {
					if shape == "register" && (op == "CMPXCHG8B" || op == "CMPXCHG16B") {
						continue // The original Go pair register rows encode #UD.
					}
					body, declaration := x86ResultCompareExchangeFixture(target.arch, op, shape == "LOCK-memory", shape == "register")
					name := strings.ReplaceAll(op+"_"+shape, "-", "_")
					source.WriteString(strings.Replace(body, "·cas(SB)", "·"+name+"(SB)", 1))
					declarations.WriteString(strings.Replace(declaration, "func cas(", "func "+name+"(", 1) + "\n")
				}
			}
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			t.Logf("ORIGINAL_CAS_RESULT_OBJECT: %+v", receipt)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("the complete original CAS family lost its result proof", err)
					}
					for _, optimizeIR := range []bool{false, true} {
						input := ir
						if optimizeIR {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimizeIR, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86CompareExchangeResultOriginalGoBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct{ name, from, to string }{
			{"label-before-body", "LOCK\n", "LOCK\nbody:\n"},
			{"jump-into-body", "LOCK\n", "JMP 2(PC)\nLOCK\n"},
			{"conditional-entry", "LOCK\n", "CMPL AX,$0\nJEQ 2(PC)\nLOCK\n"},
			{"detached-prefix", "LOCK\n", "LOCK\nNOP\n"},
			{"undefined-effect", "SETEQ ret+", "FSIN\nSETEQ ret+"},
		} {
			t.Run(arch+"/Go-accepted-Context/"+row.name, func(t *testing.T) {
				source, declaration := x86ResultCompareExchangeFixture(arch, "CMPXCHGL", true, false)
				source = strings.Replace(source, row.from, row.to, 1)
				requireLEANativeGoObject(t, arch, source, true)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Go-valid source acquired an unbound prefix or effect", api, err)
					}
				}
			})
		}
		t.Run(arch+"/Go-rejected/operand-prefix", func(t *testing.T) {
			source, _ := x86ResultCompareExchangeFixture(arch, "CMPXCHGL", true, false)
			requireLEANativeGoObject(t, arch, strings.Replace(source, "LOCK\n", "LOCK AX\n", 1), false)
		})
	}
}
