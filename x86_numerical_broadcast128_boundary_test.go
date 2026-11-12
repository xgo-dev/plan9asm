package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestX86NumericalBroadcast128OriginalGoBoundaries(t *testing.T) {
	// Both official _yvbroadcastf128 rows are VEX.256.66.0F38.W0,
	// memory-only m128 -> Y. Source addresses and physical banks are
	// orthogonal to the F/I opcode; original Go supplies every byte and PC.
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			mode, last := 32, 7
			addresses := []string{"(AX)", "-128(AX)", "127(AX)", "-129(AX)", "128(AX)",
				"(SP)", "(BP)", "(AX)(CX*1)", "32(AX)(CX*2)", "-32(AX)(DX*4)",
				"305419896(AX)(BX*8)", "64(CX*4)", "305419896", "table+16(SB)", "8(AX)(FS)", "8(AX)(GS)"}
			if arch == "amd64" {
				mode, last = 64, 15
				addresses = append(addresses, "(R8)", "128(R15)(R9*8)", "-129(R12)(R13*2)", "(R13)")
			}
			var rows []string
			for _, op := range []string{"VBROADCASTF128", "VBROADCASTI128"} {
				for _, address := range addresses {
					for _, destination := range []int{0, last} {
						rows = append(rows, fmt.Sprintf("%s %s,Y%d", op, address, destination))
					}
				}
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nRET")
			if len(pcs) != len(rows)+1 {
				t.Fatal("original Go did not preserve every complete family row", len(rows), len(pcs))
			}
			original := bytes.Clone(code)
			for index, row := range rows {
				t.Run(fmt.Sprint(index), func(t *testing.T) {
					instruction := code[pcs[index]:pcs[index+1]]
					length, err := x86NumericalVectorBoundary(instruction, mode)
					if err != nil || length != len(instruction) {
						t.Fatalf("actual Go %s: boundary=%d/%d: %v", row, length, len(instruction), err)
					}
					if mode == 64 && strings.Contains(row, "(SB)") {
						if _, _, known, err := decodedX86VBROADCAST128Instruction(instruction, mode); !known || err == nil {
							t.Fatal("physical RIP observation granted a raw source address", known, err)
						}
					}
					for end := 0; end < len(instruction); end++ {
						if _, err := x86NumericalVectorBoundary(instruction[:end], mode); err == nil {
							t.Fatalf("accepted truncated original %s at %d/%d", row, end, len(instruction))
						}
					}
				})
			}
			boundaries, _, err := x86NumericalNativeBoundaries(code, mode)
			if err != nil || len(boundaries) != len(pcs) || !bytes.Equal(code, original) {
				t.Fatal("complete original machine boundary inventory changed", err, len(boundaries), len(pcs))
			}
			for index, boundary := range boundaries {
				if boundary.PC != pcs[index] {
					t.Fatal("machine boundary lost its original Go PC", index, boundary, pcs[index])
				}
			}
		})
	}
}

func TestX86NumericalBroadcast128RejectsReservedEncodings(t *testing.T) {
	for _, opcode := range []byte{0x1a, 0x5a} {
		for _, mode := range []int{32, 64} {
			for _, row := range []struct {
				name string
				code []byte
			}{
				{"register", []byte{0xc4, 0xe2, 0x7d, opcode, 0xc1}},
				{"width128", []byte{0xc4, 0xe2, 0x79, opcode, 0x13}},
				{"vvvv", []byte{0xc4, 0xe2, 0x75, opcode, 0x13}},
				{"W1", []byte{0xc4, 0xe2, 0xfd, opcode, 0x13}},
				{"address_override", []byte{0x67, 0xc4, 0xe2, 0x7d, opcode, 0x13}},
			} {
				t.Run(fmt.Sprintf("%x/%d/%s", opcode, mode, row.name), func(t *testing.T) {
					if _, err := x86NumericalVectorBoundary(row.code, mode); err == nil {
						t.Fatalf("unregistered physical format became a native boundary: %x", row.code)
					}
				})
			}
		}
		for _, prefix := range []byte{0x62, 0xc2, 0xa2} {
			t.Run(fmt.Sprintf("%x/386/extended_%x", opcode, prefix), func(t *testing.T) {
				code := []byte{0xc4, prefix, 0x7d, opcode, 0x14, 0x88}
				if _, err := x86NumericalVectorBoundary(code, 32); err == nil {
					t.Fatalf("extended physical bank became a 386 boundary: %x", code)
				}
			})
		}
	}
}
