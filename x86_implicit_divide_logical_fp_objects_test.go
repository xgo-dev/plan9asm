package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Both dividend halves and the divisor are independent real arguments. The
// result exposes complete AX/DX: B packs quotient/remainder into AL/AH and
// retains DX, W retains upper bytes, L clears the upper AMD64 halves.
func x86LogicalFPDivideSource(name, op, arch string, bits int, registerControl bool) (string, string) {
	word, move, resultType := 8, "MOVQ", "uint64"
	if arch == "386" {
		word, move, resultType = 4, "MOVL", "uint32"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s low+0(FP),AX\n%s high+8(FP),DX\n", name, 24+2*word, move, move)
	if registerControl {
		suffix := map[int]string{8: "B", 16: "W", 32: "L", 64: "Q"}[bits]
		source += "MOV" + suffix + " divisor+16(FP),CX\n" + op + " CX\n"
	} else {
		source += op + " divisor+16(FP)\n"
	}
	source += fmt.Sprintf("%s AX,quotient+24(FP)\n%s DX,remainder+%d(FP)\nRET\n", move, move, 24+word)
	return source, fmt.Sprintf("func %s(low,high,divisor uint64) (quotient %s,remainder %s)\n", name, resultType, resultType)
}

func TestX86ImplicitDivideLogicalFPOriginalGoAndThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("logical FP division original objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var original, controls, declarations strings.Builder
			members := 0
			for _, row := range x86ImplicitDivideOracle {
				if target.arch == "386" && row.bits == 64 {
					continue
				}
				name := fmt.Sprint("LogicalFPDivide", members)
				source, declaration := x86LogicalFPDivideSource(name, row.name, target.arch, row.bits, false)
				control, _ := x86LogicalFPDivideSource(name, row.name, target.arch, row.bits, true)
				original.WriteString(source)
				controls.WriteString(control)
				declarations.WriteString(declaration)
				members++
			}
			want := 8
			if target.arch == "386" {
				want = 6
			}
			if members != want {
				t.Fatal("complete logical FP width/signedness source inventory changed", members)
			}
			// Actual Go proves both whole programs before the public consumers.
			// The register control changes only divisor transport, not inputs,
			// dividend widths, output slots or the native division operation.
			x86LEAActualTargetGoObject(t, target.arch, target.triple, original.String())
			x86LEAActualTargetGoObject(t, target.arch, target.triple, controls.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					control, err := x86ScalarFPBitViewAPI(t, controls.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || control == "" {
						t.Fatal("complete register-divisor control failed before logical FP division", err)
					}
					ir, err := x86ScalarFPBitViewAPI(t, original.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete owned logical FP divisor lost its original #DE continuation", err)
					}
					for _, pipeline := range []struct{ name, ir, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2/backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							if strings.Count(pipeline.ir, "asm sideeffect") != members ||
								regexp.MustCompile(`\b(?:sdiv|udiv|srem|urem)\b`).MatchString(pipeline.ir) {
								t.Fatal("logical division lost a mandatory native opcode or became LLVM poison")
							}
							x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
						})
					}
				})
			}
		})
	}
}
