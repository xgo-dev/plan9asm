package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86Logical386FrameAliasSource(body string) string {
	return "TEXT ·FrameAlias(SB),4,$0-12\n" + body + "\nMOVL b+4(FP),AX\nMOVL AX,ret+8(FP)\nRET\n"
}

func TestX86Logical386FrameAliasesThreeAPIsAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	const declaration = "func FrameAlias(a,b uint32) uint32"
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		for _, row := range []struct{ name, body string }{
			{"byte", "LEAL a+0(FP),SI\nMOVB $41,4(SI)"},
			{"word", "LEAL a+0(FP),SI\nMOVW $41,4(SI)"},
			{"long", "LEAL a+0(FP),SI\nMOVL $41,4(SI)"},
			{"copied", "LEAL a+0(FP),SI\nMOVL SI,DI\nMOVL $41,4(DI)"},
			{"affine", "LEAL a+0(FP),SI\nLEAL 4(SI),DI\nMOVL $41,(DI)"},
			{"readback", "LEAL a+0(FP),SI\nMOVL $41,4(SI)\nMOVL 4(SI),BX\nMOVL BX,ret+8(FP)"},
		} {
			t.Run(triple+"/"+row.name, func(t *testing.T) {
				source := x86Logical386FrameAliasSource(row.body)
				x86LEAActualTargetGoObject(t, "386", triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", triple, api)
					if err != nil {
						t.Fatal("ordinary386 logical parameter copies lost a bounded alias", api, err)
					}
					if !strings.Contains(ir, "%classic_frame = alloca") {
						t.Fatal("contiguous logical frame alias has no actual storage")
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86Logical386FrameAliasesCannotEscapeOrInventBytes(t *testing.T) {
	const declaration = "func FrameAlias(a,b uint32) uint32"
	for _, row := range []struct{ name, body string }{
		{"negative", "LEAL a+0(FP),SI\nMOVL $41,-4(SI)"},
		{"past-end", "LEAL a+0(FP),SI\nMOVL $41,12(SI)"},
		{"partial-overwrite", "LEAL a+0(FP),SI\nMOVW $0,SI\nMOVL $41,4(SI)"},
		{"index", "LEAL a+0(FP),SI\nMOVL $0,DI\nMOVL $41,4(SI)(DI*1)"},
		{"escape", "LEAL a+0(FP),SI\nMOVL SI,ret+8(FP)"},
		{"numeric-observation", "LEAL a+0(FP),SI\nTESTL SI,SI"},
		{"unknown-store", "LEAL a+0(FP),SI\nMOVL DX,4(SI)"},
		{"missing-alias-join", "MOVL a+0(FP),AX\nTESTL AX,AX\nJE joined\nLEAL a+0(FP),SI\njoined:\nMOVL $41,4(SI)"},
		{"different-alias-join", "MOVL a+0(FP),AX\nTESTL AX,AX\nJE other\nLEAL a+0(FP),SI\nJMP joined\nother:\nLEAL b+4(FP),SI\njoined:\nMOVL $41,4(SI)"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%s/%s", row.name, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, x86Logical386FrameAliasSource(row.body), declaration,
					"386", "i386-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("logical frame alias invented numerical/address/escape permission", err)
				}
			})
		}
	}
}
