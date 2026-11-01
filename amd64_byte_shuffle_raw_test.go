package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ByteShuffleRawWIGAndPhysicalMasks(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, width := range []byte{0, 4} {
			for _, w := range []byte{0, 0x80} {
				code := []byte{0xc4, 0xe2, 0x71 | width | w, 0x00, 0xd0}
				ins, size, known, err := decodedX86VPSHUFBInstruction(code, mode)
				if !known || err != nil || size != len(code) || ins.Op != "VPSHUFB" {
					t.Errorf("VEX.WIG mode=%d code=%x: size=%d known=%t err=%v", mode, code, size, known, err)
				}
			}
		}
		for width := byte(0); width < 3; width++ {
			for mask := byte(0); mask < 8; mask++ {
				for _, zero := range []byte{0, 0x80} {
					if mask == 0 && zero != 0 {
						continue
					}
					for _, w := range []byte{0, 0x80} {
						code := []byte{0x62, 0xf2, 0x75 | w, 8 | width<<5 | mask | zero, 0x00, 0xd0}
						t.Run(fmt.Sprintf("%d/%x", mode, code), func(t *testing.T) {
							ins, size, known, err := decodedX86VPSHUFBInstruction(code, mode)
							if !known || err != nil || size != len(code) {
								t.Fatalf("physical EVEX inherited named operand limit or W0: size=%d known=%t err=%v", size, known, err)
							}
							arch := "amd64"
							if mode == 32 {
								arch = "386"
							}
							if !ins.x86Encoded {
								t.Fatal("decoder lost physical encoding identity")
							}
							if _, known, err := x86ByteShuffleProperties(ins.Op, ins, arch); !known || err != nil {
								t.Fatal("typed physical consumer", known, err)
							}
							ins.x86Encoded = false
							if _, _, err := x86ByteShuffleProperties(ins.Op, ins, arch); mode == 32 && mask != 0 && err == nil {
								t.Fatal("named mode32 form acquired physical decoder authority")
							}
						})
					}
				}
			}
		}
	}
}

func TestX86ByteShuffleRawThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var codes [][]byte
	for _, width := range []byte{0, 4} {
		for _, w := range []byte{0, 0x80} {
			codes = append(codes, []byte{0xc4, 0xe2, 0x71 | width | w, 0x00, 0xd0})
		}
	}
	for width := byte(0); width < 3; width++ {
		for _, mask := range []byte{1, 7} {
			for _, zero := range []byte{0, 0x80} {
				for _, w := range []byte{0, 0x80} {
					codes = append(codes, []byte{0x62, 0xf2, 0x75 | w, 8 | width<<5 | mask | zero, 0x00, 0xd0})
				}
			}
		}
	}
	var source, declarations strings.Builder
	for index, code := range codes {
		fmt.Fprintf(&declarations, "func RawShuffle%d()\n", index)
		fmt.Fprintf(&source, "TEXT ·RawShuffle%d(SB),4,$0-0\n", index)
		for _, b := range code {
			fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
		}
		source.WriteString("RET\n")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, "raw-byte-shuffle-"+api)
			}
		})
	}
}

func TestX86ByteShuffleReservedRawForms(t *testing.T) {
	for _, code := range [][]byte{
		{0xc4, 0xe2, 0x70, 0, 0xd0},             // Wrong mandatory prefix.
		{0xc4, 0xe2, 0x71, 0},                   // Truncated ModRM.
		{0x62, 0xf2, 0x75, 0x68, 0, 0xd0},       // Reserved LL.
		{0x62, 0xf2, 0x75, 0x18, 0, 0xd0},       // No broadcast/rounding.
		{0x62, 0xf2, 0x75, 0x88, 0, 0xd0},       // Zeroing without mask.
		{0x67, 0x62, 0xf2, 0x75, 0x08, 0, 0x10}, // Unbound address size.
	} {
		for _, mode := range []int{32, 64} {
			if _, _, known, err := decodedX86VPSHUFBInstruction(code, mode); !known || err == nil {
				t.Fatalf("reserved byte shuffle accepted: mode=%d code=%x known=%t err=%v", mode, code, known, err)
			}
		}
	}
}
