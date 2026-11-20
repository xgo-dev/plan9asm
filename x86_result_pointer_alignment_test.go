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
