package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// AT&T needs the source-width alias when an m128/m256 conversion has the same
// X128 destination. Register/broadcast forms keep their canonical mnemonic.
// This recognizes only those two aliases and binds the actual same-call *m
// operand to its independent width; another call or a register input cannot
// supply the missing memory tuple.
func x86PackedPrecisionNativeMemoryAlias(assembly, constraints, arguments, operation string) bool {
	if operation != "VCVTPD2PS" {
		return false
	}
	mnemonic, operands, present := strings.Cut(assembly, " ")
	width := map[string]int{"vcvtpd2psx": 16, "vcvtpd2psy": 32}[mnemonic]
	if !present || width == 0 {
		return false
	}
	masked := operands == "$2, $0 {%k1}" || operands == "$2, $0 {%k1} {z}"
	if operands != "$2, $0" && !masked {
		return false
	}
	want := "=x,0,*m,~{memory},~{fpsr}"
	if strings.HasPrefix(constraints, "=v,") {
		want = "=v,0,*m,~{memory},~{fpsr}"
	}
	if masked {
		want = "=v,0,*m,r,~{k1},~{memory},~{fpsr}"
	}
	return constraints == want && strings.HasPrefix(arguments, "(<4 x float> ") &&
		strings.Count(arguments, "elementtype(") == 1 &&
		strings.Contains(arguments, fmt.Sprintf(", ptr elementtype([%d x i8]) %%", width))
}

func TestX86PackedPrecisionOpcodeReceiptBindsAliasAndActualTuple(t *testing.T) {
	for _, alias := range []struct {
		name  string
		width int
	}{{"vcvtpd2psx", 16}, {"vcvtpd2psy", 32}} {
		for _, mode := range []string{"VEX", "EVEX", "merge", "zero"} {
			t.Run(alias.name+"/"+mode, func(t *testing.T) {
				prefix, suffix, constraints, mask := "", "", "=x,0,*m,~{memory},~{fpsr}", ""
				if mode != "VEX" {
					prefix, constraints = "{evex} ", "=v,0,*m,~{memory},~{fpsr}"
				}
				if mode == "merge" || mode == "zero" {
					prefix, suffix = "kmovw ${3:k}, %k1; "+prefix, " {%k1}"
					constraints, mask = "=v,0,*m,r,~{k1},~{memory},~{fpsr}", ", i32 %mask"
				}
				if mode == "zero" {
					suffix += " {z}"
				}
				line := fmt.Sprintf("  %%result = tail call <4 x float> asm sideeffect %q, %q(<4 x float> %%old, ptr elementtype([%d x i8]) %%input%s) #4",
					prefix+alias.name+" $2, $0"+suffix, constraints, alias.width, mask)
				if !x86ScalarPrecisionNativeEffectLine(line, "VCVTPD2PS") {
					t.Fatal("actual source-width memory alias was rejected", line)
				}
				for _, mutation := range []struct{ name, source string }{
					{"crossed-width", strings.Replace(line, fmt.Sprint(alias.width, " x i8"), fmt.Sprint(48-alias.width, " x i8"), 1)},
					{"broadcast-width", strings.Replace(line, fmt.Sprint(alias.width, " x i8"), "8 x i8", 1)},
					{"extended-alias", strings.Replace(line, alias.name, alias.name+"q", 1)},
					{"different-opcode", strings.Replace(line, alias.name, "vcvtps2pd", 1)},
					{"register-constraint", strings.Replace(line, "*m", "v", 1)},
					{"register-input", strings.Replace(line, fmt.Sprintf("ptr elementtype([%d x i8]) %%input", alias.width), "<4 x float> %input", 1)},
					{"wrong-source-operand", strings.Replace(line, alias.name+" $2", alias.name+" $1", 1)},
					{"missing-memory-effect", strings.Replace(line, "~{memory}", "~{cc}", 1)},
					{"missing-status-effect", strings.Replace(line, "~{fpsr}", "~{cc}", 1)},
					{"missing-side-effect", strings.Replace(line, "asm sideeffect", "asm", 1)},
					{"comment", strings.Replace(line, alias.name, "# "+alias.name, 1)},
					{"another-opcode", strings.Replace(line, alias.name, "nop; "+alias.name, 1)},
					{"another-tuple-argument", strings.Replace(line, "%input", fmt.Sprintf("%%input, ptr elementtype([%d x i8]) %%extra", alias.width), 1)},
					{"another-call-width", strings.Replace(line, fmt.Sprint(alias.width, " x i8"), "8 x i8", 1) + "\n" + line},
				} {
					t.Run(mutation.name, func(t *testing.T) {
						if x86ScalarPrecisionNativeEffectLine(mutation.source, "VCVTPD2PS") {
							t.Fatal("alias receipt borrowed an unbound opcode, input, width or side effect", mutation.source)
						}
					})
				}
				for _, operation := range []string{"VCVTPS2PD", "VCVTSD2SS", "VCVTSS2SD"} {
					if x86ScalarPrecisionNativeEffectLine(line, operation) {
						t.Fatal("an alias was accepted for a different canonical operation", operation)
					}
				}
			})
		}
	}
}
