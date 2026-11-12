package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

// A bool parameter contributes one actual initialized byte to the private
// classic frame. Its alignment gap does not, and NUM never certifies I1 RET.
func TestX86Logical386BoolInputHasNumericByteAliases(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86AddressMemoryTargets("386") {
		for _, row := range []struct{ name, body string }{
			{"read", "MOVB (AX),BX"},
			{"copied", "MOVL AX,SI\nMOVB (SI),BX"},
			{"affine", "LEAL 0(AX),SI\nMOVB (SI),BX"},
			{"private-raw-byte", "MOVB $2,(AX)\nMOVB (AX),BX"},
		} {
			t.Run(target+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·ReadByte(SB),4,$0-5\nLEAL x+0(FP),AX\n" + row.body + "\nMOVB BX,ret+4(FP)\nRET\n"
				x86LEAActualTargetGoObject(t, "386", target, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func ReadByte(x bool) uint8", "386", target, api)
					if err != nil {
						t.Fatal("actual bool input byte lost its independent numeric view", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target, text, level)
						}
					}
				}
			})
		}
	}
}

func TestX86Logical386BoolNumericAliasesKeepByteAndCanonicalBoundaries(t *testing.T) {
	for _, row := range []struct{ name, body string }{
		{"padding", "MOVB 1(AX),BX"},
		{"wide-padding", "MOVW (AX),BX"},
		{"unwritten-result", "MOVB 4(AX),BX"},
		{"past-frame", "MOVB 5(AX),BX"},
		{"partial-copy", "MOVW AX,SI\nMOVB (SI),BX"},
		{"numeric-address", "TESTL AX,AX\nMOVB (AX),BX"},
		{"unknown-store", "MOVB DX,(AX)\nMOVB (AX),BX"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				source := "TEXT ·ReadByte(SB),4,$0-5\nLEAL x+0(FP),AX\n" + row.body + "\nMOVB BX,ret+4(FP)\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, "func ReadByte(x bool) uint8", "386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("bool byte granted padding, undefined bytes or address data", err)
				}
			})
		}
	}
	for _, value := range []int{2, 3, 255} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("noncanonical-%d/%s", value, api), func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·ReadBool(SB),4,$0-5\nLEAL x+0(FP),AX\nMOVB $%d,(AX)\nMOVB (AX),BX\nMOVB BX,ret+4(FP)\nRET\n", value)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func ReadBool(x bool) bool", "386", "i386-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("numeric byte alias supplied an unproved canonical bool return", err)
				}
			})
		}
	}
}
