package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86AlignedPointerDeltaSource(arch, mask string, separateOrigins bool) string {
	word, suffix := 8, "Q"
	if arch == "386" {
		word, suffix = 4, "L"
	}
	move := "MOV" + suffix
	symbol, input, other := "·Delta(SB)", "p+0(FP)", "q+4(FP)"
	if arch == "amd64" {
		symbol, input, other = "·Delta<ABIInternal>(SB)", "AX", "BX"
	}
	base := "DI"
	if separateOrigins {
		base = other
	}
	body := fmt.Sprintf("%s %s,DI\n%s %s,SI\nADD%s $32,DI\nAND%s $%s,DI\nSUB%s DI,SI\n",
		move, input, move, base, suffix, suffix, mask, suffix)
	if arch == "amd64" {
		body += "RDTSC\nMOVQ SI,AX\n" // Require the existing complete register-entry audit.
	} else {
		body += "MOVL SI,ret+8(FP)\n"
	}
	return fmt.Sprintf("TEXT %s,4,$0-%d\n%sRET\n", symbol, 3*word, body)
}

func TestX86AlignedPointerDifferenceThreeAPIs(t *testing.T) {
	const declaration = "func Delta(p,q *byte) uintptr\n"
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"386", "i386-unknown-linux-gnu"},
	} {
		for _, row := range []struct {
			name, mask string
			separate   bool
			pass       bool
		}{
			{"complement", "~31", false, true},
			{"signed", "-32", false, true},
			{"sparse", "-48", false, false},
			{"all ones", "-1", false, false},
			{"different origins", "~31", true, false},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				source := x86AlignedPointerDeltaSource(target.arch, row.mask, row.separate)
				if target.arch == "amd64" {
					requireAMD64RegisterResultGoObject(t, source)
				} else {
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if row.pass {
							if err != nil || strings.TrimSpace(ir) == "" {
								t.Fatal("aligned continuation lost its same-origin delta", err)
							}
							x86NumericNativeAddressObject(t, ir, target.triple)
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unrelated bits acquired a same-origin delta", err)
						}
					})
				}
			})
		}
	}
}

func TestX86MaskedPointerXORThreeAPIs(t *testing.T) {
	const declaration = "func view(p *byte) uintptr\n"
	for _, target := range []struct{ arch, triple, suffix string }{
		{"amd64", "x86_64-unknown-linux-gnu", "Q"},
		{"386", "i386-unknown-linux-gnu", "L"},
	} {
		for _, row := range []struct {
			name, mask, gap, operand string
			pass                     bool
		}{
			{"vector load", "31", "MOVOU (DI),X0\n", "CX", true},
			{"full-width zero mask", "0", "", "CX", true},
			{"immediate", "31", "", "$31", true},
			{"bounded on both paths", "31", "JE join\nANDL $15,CX\njoin:\n", "CX", true},
			{"unknown on one path", "31", "JE join\nMOVL $-1,CX\njoin:\n", "CX", false},
			{"replaced mask register", "31", "MOV" + target.suffix + " $-1,CX\n", "CX", false},
			{"partial overwrite", "31", "MOVB $1,CH\n", "CX", false},
			{"unbounded immediate", "31", "", "$-1", false},
		} {
			t.Run(target.arch+"/"+row.name, func(t *testing.T) {
				s := target.suffix
				body := fmt.Sprintf("MOV%s p+0(FP),DI\nMOV%s DI,CX\nAND%s $%s,CX\n%sXOR%s %s,DI\nSUB%s p+0(FP),DI\nMOV%s DI,ret+RESULT(FP)",
					s, s, s, row.mask, row.gap, s, row.operand, s, s)
				source := x86ResultGPSIMDAdmissionSource(t, target.arch, declaration, body)
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if row.pass {
						if err != nil || ir == "" {
							t.Fatalf("%s: bounded XOR lost the caller address: %v", api, err)
						}
						x86NumericNativeAddressObject(t, ir, target.triple)
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s: unproven mask acquired an address bound: %v", api, err)
					}
				}
			})
		}
	}
}
