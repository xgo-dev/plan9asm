package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86StringCompareResultBody(arch, opcode, prefix, direction string, flags bool) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	body := fmt.Sprintf("%s left+0(FP),SI\n%s right+%d(FP),DI\n%s n+%d(FP),CX\n%s needle+%d(FP),AX\n%s\n",
		move, move, word, move, 2*word, move, 3*word, direction)
	if prefix != "" {
		body += prefix + "\n"
	}
	body += opcode + "\n"
	if flags {
		body += "MOVL $0,BX\nSETEQ BL\n" + move + " BX,ret+RESULT(FP)"
	} else {
		body += move + " CX,ret+RESULT(FP)"
	}
	return body
}

func x86StringCompareCompleteSource(t *testing.T, arch string) (string, string) {
	t.Helper()
	const declaration = "func view(left,right *byte,n,needle uintptr) uintptr"
	var source, declarations strings.Builder
	for _, stem := range []string{"SCAS", "CMPS"} {
		widths := "BWLQ"
		if arch == "386" {
			widths = "BWL"
		}
		for _, width := range widths {
			for index, prefix := range []string{"", "REP", "REPN"} {
				for _, direction := range []string{"CLD", "STD"} {
					body := x86StringCompareResultBody(arch, stem+string(width), prefix, direction, prefix == "")
					text := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
					name := fmt.Sprintf("view%s%c%d%s", stem, width, index, direction)
					source.WriteString(strings.Replace(text, "·view(SB)", "·"+name+"(SB)", 1))
					declarations.WriteString(strings.Replace(declaration, "view(", name+"(", 1) + "\n")
				}
			}
		}
	}
	want := 48
	if arch == "386" {
		want = 36
	}
	if strings.Count(source.String(), "TEXT ") != want || strings.Count(declarations.String(), "func ") != want {
		t.Fatal("complete independent SCAS/CMPS source inventory changed")
	}
	return source.String(), declarations.String()
}

func TestX86StringCompareCompleteGoObjects(t *testing.T) {
	for _, target := range dataRelocationTargets {
		if target.arch != ArchAMD64 {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			source, _ := x86StringCompareCompleteSource(t, target.goarch)
			dataRelocationGoObject(t, source, target.goos, target.goarch, true)
		})
	}
}

func TestX86StringCompareConditionalFactsRequireWholeSource(t *testing.T) {
	const declaration = "func view(left,right *byte,n,needle uintptr) uintptr"
	for _, target := range x86RawReturnTargets {
		word, move := 8, "MOVQ"
		if target.arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range []struct {
			name string
			edit func(string) string
		}{
			{"missing-result", func(body string) string { return strings.Replace(body, "CX,ret+RESULT(FP)", "CX,BX", 1) }},
			{"missing-needle", func(body string) string {
				return strings.Replace(body, fmt.Sprintf("%s needle+%d(FP),AX\n", move, 3*word), "", 1)
			}},
			{"not-a-pointer", func(body string) string {
				return strings.Replace(body, fmt.Sprintf("%s right+%d(FP),DI", move, word), fmt.Sprintf("%s n+%d(FP),DI", move, 2*word), 1)
			}},
			{"partial-zero", func(string) string { return "MOVW $0,CX\nREP\nSCASB\n" + move + " $7,ret+RESULT(FP)" }},
			{"overwritten-zero", func(string) string { return "MOVL $0,CX\nMOVB $1,CL\nREP\nSCASB\n" + move + " $7,ret+RESULT(FP)" }},
			{"zero-cannot-define-ZF", func(string) string {
				return "MOVL $0,CX\nREP\nSCASB\nMOVL $0,BX\nSETEQ BL\n" + move + " BX,ret+RESULT(FP)"
			}},
			{"zero-cannot-define-DF", func(body string) string {
				return "MOVL $0,CX\nREP\nSCASB\n" + strings.Replace(body, "CLD\n", "", 1)
			}},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					body := row.edit(x86StringCompareResultBody(target.arch, "SCASB", "REPN", "CLD", false))
					source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err == nil || ir != "" {
						t.Fatal("conditional continuation manufactured a missing input, result or status fact", err)
					}
				})
			}
		}
	}
}

func TestX86StringCompareNumericalContinuationThreeAPIs(t *testing.T) {
	const declaration = "func view(left,right *byte,n,needle uintptr) uintptr"
	for _, target := range x86RawReturnTargets {
		for _, stem := range []string{"SCAS", "CMPS"} {
			widths := "BWLQ"
			if target.arch == "386" {
				widths = "BWL"
			}
			for _, width := range widths {
				for _, prefix := range []string{"", "REP", "REPN"} {
					for _, direction := range []string{"CLD", "STD"} {
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(fmt.Sprintf("%s/%s%c/%s/%s/%s", target.triple, stem, width, prefix, direction, api), func(t *testing.T) {
								body := x86StringCompareResultBody(target.arch, stem+string(width), prefix, direction, prefix == "")
								source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
								if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil || ir == "" {
									t.Fatal("complete comparison/count result rejected", err)
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestX86StringCompareZeroCountPreservesOriginalFlags(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		move := "MOVQ"
		if target.arch == "386" {
			move = "MOVL"
		}
		for _, prefix := range []string{"REP", "REPN"} {
			for _, flags := range []bool{false, true} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/flags%t/%s", target.triple, prefix, flags, api), func(t *testing.T) {
						// With zero iterations neither a source pointer, an
						// accumulator value nor incoming DF is observed.
						body := "MOVL $0,CX\n"
						if flags {
							body += "CMPL AX,AX\n"
						}
						body += prefix + "\nSCASB\n"
						if flags {
							body += "MOVL $0,BX\nSETEQ BL\n" + move + " BX,ret+RESULT(FP)"
						} else {
							body += move + " CX,ret+RESULT(FP)"
						}
						source := x86ResultGPSIMDAdmissionSource(t, target.arch, "func view() uintptr", body)
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uintptr", target.arch, target.triple, api); err != nil || ir == "" {
							t.Fatal("zero-count comparison changed FLAGS or observed an unused input", err)
						}
					})
				}
			}
		}
	}
}

func TestX86StringCompareCannotInventIncomingFlagsOrDirection(t *testing.T) {
	const declaration = "func view(left,right *byte,n,needle uintptr) uintptr"
	for _, target := range x86RawReturnTargets {
		for _, role := range []string{"unknown DF", "unknown initial ZF", "partial counter", "skipped prefix"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+role+"/"+api, func(t *testing.T) {
					body := x86StringCompareResultBody(target.arch, "SCASB", "REPN", "CLD", false)
					switch role {
					case "unknown DF":
						body = strings.Replace(body, "CLD\n", "", 1)
					case "unknown initial ZF":
						body = x86StringCompareResultBody(target.arch, "SCASB", "REP", "CLD", true)
					case "partial counter":
						// A low16 zero is not a full native count of zero.
						move := "MOVQ"
						if target.arch == "386" {
							move = "MOVL"
						}
						body = "MOVW $0,CX\nREPN\nSCASB\n" + move + " CX,ret+RESULT(FP)"
					case "skipped prefix":
						body = strings.Replace(body, "REPN\nSCASB", "CMPL AX,AX\nJE body\nREPN\nbody:\nSCASB", 1)
					}
					source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("comparison fabricated an unproved status, count, direction or prefix", err)
					}
				})
			}
		}
	}
}
