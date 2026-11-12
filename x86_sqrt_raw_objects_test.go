package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86SqrtInitializedRawFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var codes [][]byte
	for pp := byte(0); pp < 4; pp++ {
		for length := byte(0); length < 2; length++ {
			if pp >= 2 && length != 0 {
				continue
			}
			for w := byte(0); w < 2; w++ {
				code := []byte{0xc4, 0xe1, 0x78 | pp | length<<2 | w<<7, 0x51, 0xd1}
				if pp >= 2 {
					code[2], code[4] = 0x68|pp|w<<7, 0xd9
				}
				codes = append(codes, code)
			}
		}
		for length := byte(0); length < 4; length++ {
			if pp < 2 && length == 3 {
				continue
			}
			for _, mask := range []byte{0, 1, 0x81} {
				code := []byte{0x62, 0xf1, 0x7c | pp, 0x08 | length<<5 | mask, 0x51, 0xd1}
				if pp >= 2 {
					code[2], code[5] = 0x6c|pp, 0xd9
				}
				if pp&1 != 0 {
					code[2] |= 0x80
				}
				codes = append(codes, code)
			}
		}
	}
	if len(codes) != 54 {
		t.Fatal("physical sqrt fixture inventory changed", len(codes))
	}
	var source, declarations strings.Builder
	for index, code := range codes {
		fmt.Fprintf(&source, "TEXT ·RawSqrt%d(SB),4,$0\nMOVL $1,AX\nKMOVD AX,K1\n", index)
		for register := 0; register < 4; register++ {
			fmt.Fprintf(&source, "VPXORD Z%d,Z%d,Z%d\n", register, register, register)
		}
		for _, value := range code {
			fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
		}
		source.WriteString("RET\n")
		fmt.Fprintf(&declarations, "func RawSqrt%d()\n", index)
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized physical sqrt source rejected", api, err)
				}
				if strings.Count(ir, "{evex} vsqrt") != 42 {
					t.Fatal("physical EVEX generation lost in actual emission", api)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}
