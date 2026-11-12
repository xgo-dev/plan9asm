package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86NonTemporalCompleteOriginalNativeBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			mode, last := 32, 7
			if arch == "amd64" {
				mode, last = 64, 31
			}
			var body strings.Builder
			for _, row := range x86NonTemporalNativeOracle {
				if !row.vector {
					continue
				}
				for _, bank := range []string{"X", "Y", "Z"} {
					for _, register := range []int{0, last} {
						for _, memory := range []string{"(AX)", "128(AX)", "-128(AX)(CX*4)", "8(AX)(GS)"} {
							first, second := fmt.Sprint(bank, register), memory
							if row.load {
								first, second = second, first
							}
							fmt.Fprintf(&body, "%s %s,%s\n", row.name, first, second)
						}
					}
				}
			}
			body.WriteString("RET\n")
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, body.String())
			boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil || len(boundaries) != len(pcs) || len(pcs) != 97 || len(scalar) != 1 {
				t.Fatalf("complete original Go non-temporal VEX/EVEX boundaries: count=%d scalar=%d err=%v", len(boundaries), len(scalar), err)
			}
			for index, boundary := range boundaries {
				if boundary.PC != pcs[index] {
					t.Fatal("non-temporal original Go PC changed", index, boundary, pcs[index])
				}
				end := int(boundary.PC) + boundary.Length
				for cut := int(boundary.PC) + 1; cut < end; cut++ {
					if _, _, err := x86NumericalNativeBoundaries(code[boundary.PC:cut], mode); err == nil {
						t.Fatal("truncated non-temporal native encoding accepted", boundary.PC, cut, end)
					}
				}
				if index == len(boundaries)-1 {
					continue // The only scalar instruction is the original RET.
				}
				physical := code[boundary.PC:end]
				prefix, known := decodeX86RawVectorEncoding(physical)
				if !known {
					t.Fatal("original Go non-temporal encoding lost its physical vector prefix")
				}
				if !prefix.evex {
					continue
				}
				start := prefix.modRM - 5
				for _, change := range []string{"mask", "zero", "broadcast", "length", "vvvv", "Vprime", "fixed", "word", "register"} {
					changed := append([]byte(nil), physical...)
					switch change {
					case "mask":
						changed[start+3] |= 1
					case "zero":
						changed[start+3] |= 0x80
					case "broadcast":
						changed[start+3] |= 0x10
					case "length":
						changed[start+3] |= 0x60
					case "vvvv":
						changed[start+2] &^= 8
					case "Vprime":
						changed[start+3] &^= 8
					case "fixed":
						changed[start+2] &^= 4
					case "word":
						changed[start+2] ^= 0x80
					case "register":
						changed[prefix.modRM] |= 0xc0
					}
					if _, _, err := x86NumericalNativeBoundaries(changed, mode); err == nil {
						t.Fatal("reserved non-temporal encoding acquired a native boundary", change, physical)
					}
				}
			}
		})
	}
}

func TestX86NonTemporalVEXWIsIgnoredUnlikeEVEX(t *testing.T) {
	// Intel SDM's four VEX rows are WIG, although Go emits W0. The
	// independent EVEX mutation controls above require each exact W0/W1.
	for _, row := range []struct {
		name string
		code []byte
	}{
		{"VMOVNTDQ", []byte{0xc4, 0xe1, 0x79, 0xe7, 0x03}},
		{"VMOVNTPD", []byte{0xc4, 0xe1, 0x79, 0x2b, 0x03}},
		{"VMOVNTPS", []byte{0xc4, 0xe1, 0x78, 0x2b, 0x03}},
		{"VMOVNTDQA", []byte{0xc4, 0xe2, 0x79, 0x2a, 0x03}},
	} {
		for _, mode := range []int{32, 64} {
			for _, word := range []byte{0, 0x80} {
				code := append([]byte(nil), row.code...)
				code[2] |= word
				ins, length, known, err := decodedX86VEXNonTemporalMoveInstruction(code, mode)
				if !known || err != nil || ins.Op != Op(row.name) || length != len(code) {
					t.Fatal("valid physical VEX.WIG form lost its native identity", row.name, mode, word, err)
				}
				boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
				if err != nil || len(boundaries) != 1 || len(scalar) != 0 {
					t.Fatal("VEX.WIG move became a scalar or incomplete native boundary", row.name, mode, word, err)
				}
			}
		}
	}
}
