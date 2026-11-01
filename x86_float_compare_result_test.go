package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These complete source programs do not borrow a caller/frame certificate or
// zero-initialized implementation slots. The opcode inventory is independent
// of the shared implementation map; existing Go-row tests own its full grammar.
func x86FloatingCompareResultPrograms(arch string) (string, string, []string) {
	var assembly, declarations strings.Builder
	var names []string
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		vector := strings.HasPrefix(opcode, "V")
		scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
		if arch == "386" && vector {
			continue // Named V compares have no Go mode32 row; raw roles stay separate.
		}
		banks := []string{"X"}
		if vector && !scalar {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			for _, mask := range []bool{false, true} {
				if mask && !vector || !mask && bank == "Z" {
					continue
				}
				name := fmt.Sprint("Compare", len(names))
				names = append(names, name)
				fmt.Fprintf(&declarations, "func %s() uint32\n", name)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-4\n", name)
				zero := "PXOR"
				if vector {
					zero = "VXORPS"
					if bank == "Z" {
						zero = "VPXORD"
					}
				}
				for _, register := range []int{0, 1} {
					operands := fmt.Sprintf("%s%d,%s%d", bank, register, bank, register)
					if vector {
						operands += fmt.Sprintf(",%s%d", bank, register)
					}
					fmt.Fprintf(&assembly, "%s %s\n", zero, operands)
				}
				destination := "X1"
				if vector {
					destination = bank + "2"
					if mask {
						destination = "K2"
					}
					fmt.Fprintf(&assembly, "%s $0,%s0,%s1,%s\n", opcode, bank, bank, destination)
				} else {
					fmt.Fprintf(&assembly, "%s X0,X1,$0\n", opcode)
				}
				if mask {
					assembly.WriteString("KMOVD K2,AX\n")
				} else {
					assembly.WriteString("MOVL " + strings.Replace(destination, bank, "X", 1) + ",AX\n")
				}
				assembly.WriteString("MOVL AX,ret+0(FP)\nRET\n")
			}
		}
	}
	return assembly.String(), declarations.String(), names
}

func TestX86FloatingCompareCompleteSourceResultObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86FloatingCompareResultPrograms(target.arch)
			expected := 18
			if target.arch == "386" {
				expected = 4
			}
			if len(names) != expected {
				t.Fatal("incomplete independent comparison result inventory", len(names), expected)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete floating compare result lost its typed byte effect", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86CompactExpandRequireAllDefinitions(t, text, names)
						if strings.Count(text, "asm sideeffect") < len(names) {
							t.Fatal("original comparison/MXCSR effects became optional numerical operations")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86FloatingCompareVoidCannotInventInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		original, _, _ := x86FloatingCompareResultPrograms(arch)
		file, err := Parse(ArchAMD64, original)
		if err != nil {
			t.Fatal(err)
		}
		for index, function := range file.Funcs {
			for _, unusedBool := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/bool-%t", arch, index, unusedBool), func(t *testing.T) {
					arguments, declaration := 0, "func Value()"
					if unusedBool {
						arguments, declaration = 1, "func Value(unused bool)"
					}
					var body strings.Builder
					fmt.Fprintf(&body, "TEXT ·Value(SB),4,$0-%d\n", arguments)
					for _, ins := range function.Instrs[1:] {
						if strings.HasPrefix(string(ins.Op), "CMP") || strings.HasPrefix(string(ins.Op), "VCMP") {
							body.WriteString(ins.Raw + "\n")
							break
						}
						body.WriteString(ins.Raw + "\n")
					}
					body.WriteString("RET\n")
					source := body.String()
					x86LEAActualTargetGoObject(t, arch, triple, source)
					first := function.Instrs[1].Raw + "\n"
					changed := strings.Replace(source, first, "", 1)
					both := strings.Replace(changed, function.Instrs[2].Raw+"\n", "", 1)
					for _, api := range []string{"text", "module", "Go"} {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); ir == "" || err != nil {
							t.Fatal("initialized Void comparison lost its original native effect", api, err)
						}
						for role, missing := range map[string]string{"first source": changed, "both sources": both} {
							if ir, err := x86ScalarFPBitViewAPI(t, missing, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void or unused bool supplied undefined comparison bytes", role, api, err)
							}
						}
					}
				})
			}
		}
	}
}
