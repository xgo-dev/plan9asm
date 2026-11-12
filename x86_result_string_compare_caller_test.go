package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86StringCompareWholeFlowPreservesExactCallerFootprint(t *testing.T) {
	const declaration = "func view(p *byte,needle uintptr) uint32"
	for _, target := range x86RawReturnTargets {
		word, move, compare, widths := 8, "MOVQ", "CMPQ", "BWLQ"
		if target.arch == "386" {
			word, move, compare, widths = 4, "MOVL", "CMPL", "BWL"
		}
		for _, stem := range []string{"SCAS", "CMPS"} {
			for _, width := range widths {
				for _, prefix := range []string{"", "REP", "REPN"} {
					for _, zero := range []bool{true, false} {
						if prefix == "" && !zero {
							continue // Bare strings execute once, independently of CX.
						}
						registers := []string{"CX"}
						if prefix != "" {
							registers = []string{"DI", "SI"}
						}
						for _, register := range registers {
							if !zero && stem == "SCAS" && register == "SI" {
								continue // This separate input is not an updated SCAS index.
							}
							for _, api := range []string{"text", "module", "Go"} {
								t.Run(fmt.Sprintf("%s/%s%c/%s/zero%t/%s/%s", target.triple, stem, width, prefix, zero, register, api), func(t *testing.T) {
									body := fmt.Sprintf("%s p+0(FP),SI\n%s p+0(FP),DI\n%s needle+%d(FP),AX\n", move, move, move, word)
									if prefix == "" {
										body += move + " p+0(FP),CX\nCLD\n"
									} else if zero {
										body += "MOVL $0,CX\n" + prefix + "\n"
									} else {
										body += "MOVL $1,CX\nCLD\n" + prefix + "\n"
									}
									body += stem + string(width) + "\n" + compare + " " + register + ",$0\nMOVL $7,ret+RESULT(FP)"
									source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
									ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
									if err != nil || ir == "" {
										t.Fatal("comparison lost independently initialized entry-derived address bits", err)
									}
									// Keep the complete original comparison above. Observing
									// its bits is not permission to access the changed cursor.
									for _, access := range []struct{ name, instruction string }{
										{"native-read", "MOVBLZX (" + register + "),DX"},
										{"native-store", "MOVB $1,(" + register + ")"},
									} {
										t.Run(access.name, func(t *testing.T) {
											changed := strings.Replace(body, compare+" "+register+",$0\n", access.instruction+"\n", 1)
											changedSource := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, changed)
											ir, err := x86ScalarFPBitViewAPI(t, changedSource, declaration, target.arch, target.triple, api)
											if zero {
												if err != nil || ir == "" {
													t.Fatal("zero iterations revoked the actual unchanged pointer", err)
												}
											} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
												t.Fatal("cursor bits acquired a reusable native memory role", err)
											}
										})
									}
								})
							}
						}
					}
				}
			}
		}
	}
}
