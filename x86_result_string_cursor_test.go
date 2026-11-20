package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Each function uses a string-derived address again. In memclr, STOSQ's DI
// flows back to the dispatch block and becomes the base of the tail stores.
func x86CountedStringCursorSource(arch string) (string, string) {
	word, suffix, widths := 8, "Q", "BWLQ"
	if arch == "386" {
		word, suffix, widths = 4, "L", "BWL"
	}
	var assembly, declarations strings.Builder
	for _, kind := range []string{"MOVS", "STOS", "LODS"} {
		for _, width := range widths {
			for _, prefix := range []string{"", "REP", "REPN"} {
				name := prefix + kind + string(width)
				symbol := "·" + name
				move := "MOV" + suffix
				var before, after string
				if arch == "amd64" {
					symbol += "<ABIInternal>"
					before = "MOVQ AX,DI\nMOVQ BX,SI\n"
					after = "RDTSC\nMOVQ $1,AX\n"
				} else {
					before = "MOVL dest+0(FP),DI\nMOVL src+4(FP),SI\nMOVL count+8(FP),CX\n"
					after = "MOVL $1,ret+12(FP)\n"
				}
				fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-%d\n%s", symbol, word*4, before)
				fmt.Fprintf(&assembly, "%s $0x5a5a5a5a,AX\nCLD\n", move)
				if prefix != "" {
					assembly.WriteString(prefix + "\n")
				}
				fmt.Fprintf(&assembly, "%s%c\n", kind, width)
				if kind != "LODS" {
					assembly.WriteString("MOVB $0x41,(DI)\n")
				}
				if kind != "STOS" {
					assembly.WriteString("MOVB $0x42,(SI)\n")
				}
				assembly.WriteString(after + "RET\n")
				fmt.Fprintf(&declarations, "func %s(dest,src *byte,count uintptr) uintptr\n", name)
			}
		}
	}
	return assembly.String(), declarations.String()
}

func TestX86CountedStringCursorThreeAPIs(t *testing.T) {
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-unknown-linux-gnu"}, {"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(target.arch, func(t *testing.T) {
			source, declarations := x86CountedStringCursorSource(target.arch)
			if target.arch == "amd64" {
				requireAMD64RegisterResultGoObject(t, source)
			} else {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("string-derived cursor could not continue to its store", err)
					}
					x86NumericNativeAddressObject(t, ir, target.triple)
				})
			}
		})
	}
}

func TestGoModule386StringCursorEntryDirection(t *testing.T) {
	const triple = "i386-unknown-linux-gnu"
	source, declarations := x86CountedStringCursorSource("386")
	source = strings.ReplaceAll(source, "CLD\n", "")
	x86LEAActualTargetGoObject(t, "386", triple, source)
	pkg := mustGoPackage(t, "cursorentry", "package cursorentry\n"+declarations)

	ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(source), "386", triple, "owned-context")
	if err != nil || ir == "" {
		t.Fatal("typed Go 386 call did not supply forward entry direction", err)
	}
	x86NumericNativeAddressObject(t, ir, triple)

	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "386", triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s: unspecified Go target acquired an entry direction: %v", api, err)
		}
	}
	withoutCounter := strings.ReplaceAll(source, "MOVL count+8(FP),CX\n", "")
	if ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(withoutCounter), "386", triple, "owned-context"); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("known direction supplied an uninitialized count", err)
	}
}
