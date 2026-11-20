package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86MOVBEOriginalInvalidImmediateIsGoRejected(t *testing.T) {
	goAssemblerOracleOutput(t, "amd64", "#include \"textflag.h\"\n"+x86MOVBEOriginalRuntimeSource, "", false)
}

func TestX86MOVBERepairedOriginalRuntimeSourceObjects(t *testing.T) {
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86RawNumericalFamilyObjects(t, x86MOVBERepairedRuntimeSource(t),
				"func movesemantics(out *[72]byte)", "amd64", triple)
		})
	}
}

func TestX86MOVBEInitializedWidthsDirectionsAndTargets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := goWordSize(target.arch), "MOVQ"
			widths := []string{"W", "WW", "L", "LL", "Q", "QQ"}
			if word == 4 {
				move, widths = "MOVL", widths[:4]
			}
			var source, declarations strings.Builder
			count := 0
			for _, width := range widths {
				for _, store := range []bool{false, true} {
					for _, raw := range []bool{false, true} {
						name, line, result := fmt.Sprint("Value", count), "MOVBE"+width+" (SI),CX", "CX"
						if store {
							line, result = "MOVBE"+width+" AX,(SI)", "AX"
						}
						if raw {
							line = x86RawNumericalInstruction(t, target.arch, line)
						}
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n"+
							"%s input+0(FP),SI\n%s value+%d(FP),AX\n%s $-1,CX\n"+
							"%s\n%s %s,ret+%d(FP)\nRET\n",
							name, word*3, move, move, word, move, line, move, result, word*2)
						fmt.Fprintf(&declarations, "func %s(input *uint64,value uintptr) uintptr\n", name)
						count++
					}
				}
			}
			if count != len(widths)*4 {
				t.Fatal("complete MOVBE alias/direction/source inventory changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}
