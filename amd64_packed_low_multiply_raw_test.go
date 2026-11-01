package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedLowMultiplyRawWIGAndPhysicalMasks(t *testing.T) {
	for _, mode := range []int{32, 64} {
		for _, length := range []byte{0, 4} {
			for _, w := range []byte{0, 0x80} {
				code := []byte{0xc4, 0xe2, 0x71 | length | w, 0x40, 0xd0}
				ins, size, known, err := decodedX86PackedMultiplyLowInstruction(code, mode)
				if !known || err != nil || size != len(code) || ins.Op != "VPMULLD" {
					t.Fatalf("VEX.WIG does not select PMULLQ: mode=%d code=%x known=%v size=%d err=%v", mode, code, known, size, err)
				}
			}
		}
		for _, qword := range []bool{false, true} {
			for length := byte(0); length < 3; length++ {
				for mask := byte(1); mask < 8; mask++ {
					for _, zero := range []bool{false, true} {
						code := encodeX86EVEXPackedMultiplyLow(qword, length, int(mask), zero, 2, 1, 0)
						ins, size, known, err := decodedX86PackedMultiplyLowInstruction(code, mode)
						if !known || err != nil || size != len(code) || !ins.x86Encoded {
							t.Fatalf("physical EVEX must not inherit named operand limit: mode=%d code=%x known=%v size=%d err=%v", mode, code, known, size, err)
						}
						arch := "amd64"
						if mode == 32 {
							arch = "386"
						}
						if _, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch); !known || err != nil {
							t.Fatal("typed consumer lost decoded physical form", ins.Raw, err)
						}
						ins.x86Encoded = false
						if _, _, err := x86PackedLowMultiplyProperties(ins.Op, ins, arch); mode == 32 && err == nil {
							t.Fatal("named mode32 instruction borrowed decoder identity")
						}
					}
				}
			}
		}
	}
}

func TestX86PackedLowMultiplyRawThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var encodings [][]byte
	for _, length := range []byte{0, 4} {
		for _, w := range []byte{0, 0x80} {
			encodings = append(encodings, []byte{0xc4, 0xe2, 0x71 | length | w, 0x40, 0xd0})
		}
	}
	for _, qword := range []bool{false, true} {
		for length := byte(0); length < 3; length++ {
			for _, mask := range []int{1, 7} {
				for _, zero := range []bool{false, true} {
					encodings = append(encodings, encodeX86EVEXPackedMultiplyLow(qword, length, mask, zero, 2, 1, 0))
				}
			}
		}
	}
	var source, declarations strings.Builder
	for i, code := range encodings {
		fmt.Fprintf(&declarations, "func RawLow%d()\n", i)
		fmt.Fprintf(&source, "TEXT ·RawLow%d(SB),4,$0-0\n", i)
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
				x86ResultInitializationObject(t, llc, target.triple, ir, "raw-low-multiply-"+api)
			}
		})
	}
}
